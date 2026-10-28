//! Typed missing context and the stored-wins merge. When a permit condition cannot be decided because a value is absent the
//! verifier names what is missing and who may supply it (principal | discharge_issuer | rs_observation | agent_declared_untrusted);
//! a supplied value never replaces a bound one. Total: no function panics, every malformed input is a deny. Port of
//! packages/pca/src/missing-context.ts; replays missing-context-vectors.json.
use crate::hash_canonical_strict;
use crate::predicates::{evaluate_condition_tri, is_group_condition, Ctx, Tri};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

pub const SUPPLIERS: [&str; 4] = ["principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted"];
const FORBIDDEN: [&str; 3] = ["__proto__", "constructor", "prototype"];
static NULL: Value = Value::Null;

/// Path (or prefix) -> who may supply it. Build one from a validated JSON object with [`supplier_table`].
pub type SupplierTable = HashMap<String, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingContext {
    pub path: String,
    pub supplier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedDecision {
    pub decision: &'static str,
    pub reason: Option<String>,
    pub missing: Vec<MissingContext>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundContext {
    pub context: Value,
    pub conflicts: Vec<String>,
    pub dropped: Vec<String>,
}

/// `Object.keys` of a parsed JSON object: canonical array-index keys first (ascending), then the rest in text order.
pub(crate) fn js_keys(o: &Map<String, Value>) -> Vec<String> {
    let idx = |k: &str| (k == "0" || (!k.starts_with('0') && !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()))).then(|| k.parse::<u64>().ok()).flatten().filter(|n| *n < u32::MAX as u64);
    let mut ints: Vec<(u64, String)> = o.keys().filter_map(|k| idx(k.as_str()).map(|n| (n, k.clone()))).collect();
    ints.sort();
    let mut out: Vec<String> = ints.into_iter().map(|(_, k)| k).collect();
    out.extend(o.keys().filter(|k| idx(k.as_str()).is_none()).cloned());
    out
}

fn u16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The longest table key equal to `path` or a segment-boundary prefix of it; unmatched is `principal`.
pub fn supplier_of<'a>(path: &str, table: &'a SupplierTable) -> &'a str {
    let mut best: Option<&String> = None;
    for k in table.keys() {
        let hit = path == k.as_str() || path.strip_prefix(k.as_str()).is_some_and(|r| r.starts_with('.'));
        if hit && best.map_or(true, |b| k.len() > b.len()) {
            best = Some(k);
        }
    }
    best.and_then(|b| table.get(b)).map_or("principal", String::as_str)
}

fn ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// `^(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*$` and no forbidden segment.
fn supplier_key_ok(k: &str) -> bool {
    let segs: Vec<&str> = k.split('.').collect();
    let root = match segs[0] {
        "action" if segs.get(1) == Some(&"params") => 2,
        "subject" | "env" => 1,
        _ => return false,
    };
    segs[root..].iter().all(|s| ident(s)) && !segs.iter().any(|s| FORBIDDEN.contains(s))
}

/// `None` = a well-formed table (an object of allowed paths to known suppliers).
pub fn supplier_table_error(t: &Value) -> Option<String> {
    let Some(o) = t.as_object() else { return Some("the supplier table must be an object".into()) };
    for k in js_keys(o) {
        if !supplier_key_ok(&k) {
            return Some(format!("bad supplier path '{k}'"));
        }
        if !o.get(&k).and_then(Value::as_str).is_some_and(|v| SUPPLIERS.contains(&v)) {
            return Some(format!("bad supplier for '{k}'"));
        }
    }
    None
}

/// The table of a JSON object (members that are not strings are skipped; validate first with [`supplier_table_error`]).
pub fn supplier_table(t: &Value) -> SupplierTable {
    t.as_object().map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()).unwrap_or_default()
}

/// Flatten a plain-object tree into dotted leaf paths. Arrays and non-plain values are leaves.
fn leaves(v: &Value, prefix: &str, out: &mut HashMap<String, Value>, depth: usize) {
    match v.as_object() {
        Some(o) if depth <= 16 && !o.is_empty() => {
            for (k, x) in o {
                if !FORBIDDEN.contains(&k.as_str()) {
                    leaves(x, &format!("{prefix}.{k}"), out, depth + 1);
                }
            }
        }
        _ => {
            out.insert(prefix.to_string(), v.clone());
        }
    }
}

fn set_path(cur: &mut Map<String, Value>, segs: &[&str], v: Value) {
    match segs {
        [] => {}
        [last] => {
            cur.insert((*last).to_string(), v);
        }
        [first, rest @ ..] => {
            if !cur.get(*first).is_some_and(Value::is_object) {
                cur.insert((*first).to_string(), Value::Object(Map::new()));
            }
            if let Some(Value::Object(next)) = cur.get_mut(*first) {
                set_path(next, rest, v);
            }
        }
    }
}

fn same(a: &Value, b: &Value) -> bool {
    matches!((hash_canonical_strict(&json!({ "v": a })), hash_canonical_strict(&json!({ "v": b }))), (Some(x), Some(y)) if x == y)
}

/// Merge request-supplied context into the bound context. Bound wins; a differing supplied value is a conflict (the call is
/// refused); a value for an `agent_declared_untrusted` path is dropped. `supplied` that is not an object is ignored.
pub fn bind_context(bound: &Value, supplied: &Value, table: &SupplierTable) -> BoundContext {
    let mut ctx = bound.clone();
    let (mut conflicts, mut dropped) = (Vec::new(), Vec::new());
    let mut flat: HashMap<String, Value> = HashMap::new();
    if let Some(sup) = supplied.as_object() {
        if let Some(p) = sup.get("action").and_then(|a| a.get("params")).filter(|p| p.is_object()) {
            leaves(p, "action.params", &mut flat, 0);
        }
        for root in ["subject", "env"] {
            if let Some(m) = sup.get(root).filter(|m| m.is_object()) {
                leaves(m, root, &mut flat, 0);
            }
        }
    }
    let mut paths: Vec<String> = flat.keys().cloned().collect();
    paths.sort_by(|a, b| u16_cmp(a, b));
    for path in paths {
        let value = &flat[&path];
        if supplier_of(&path, table) == "agent_declared_untrusted" {
            dropped.push(path);
            continue;
        }
        if let Some(cur) = Ctx::new(&ctx).resolve(&path) {
            if !same(cur, value) {
                conflicts.push(path);
            }
            continue;
        }
        let segs: Vec<&str> = path.split('.').collect();
        // a bound leaf sits above the supplied path: writing it would replace the bound value
        let blocked = (2..segs.len()).any(|i| Ctx::new(&ctx).resolve(&segs[..i].join(".")).is_some_and(|v| !v.is_object()));
        let Some(root) = ctx.as_object_mut() else {
            conflicts.push(path);
            continue;
        };
        if blocked {
            conflicts.push(path);
            continue;
        }
        if path.starts_with("action.params") {
            if matches!(root.get("action"), None | Some(Value::Null)) {
                root.insert("action".into(), json!({ "verb": "", "resource": "" }));
            }
            match root.get_mut("action").and_then(Value::as_object_mut) {
                None => {
                    conflicts.push(path); // the reference throws here; refused
                    continue;
                }
                Some(a) => {
                    if !a.get("params").is_some_and(Value::is_object) {
                        a.insert("params".into(), Value::Object(Map::new()));
                    }
                }
            }
        }
        set_path(root, &segs, value.clone());
    }
    BoundContext { context: ctx, conflicts, dropped }
}

fn collect(c: &Value, ctx: &Value, out: &mut HashSet<String>, ill: &mut bool, depth: usize) {
    if depth > 64 || !(c.is_object() || c.is_array()) {
        *ill = true;
        return;
    }
    if let (true, Some(o)) = (is_group_condition(c), c.as_object()) {
        let kids: Vec<&Value> = match o.get("all_of").or_else(|| o.get("any_of")) {
            Some(Value::Array(a)) if !a.is_empty() => a.iter().collect(),
            Some(_) => {
                *ill = true;
                return;
            }
            None => vec![o.get("not").unwrap_or(&NULL)],
        };
        for k in kids {
            collect(k, ctx, out, ill, depth + 1);
        }
        return;
    }
    if evaluate_condition_tri(c, &Ctx::new(ctx)) != Tri::Unknown {
        return;
    }
    let field = c.get("field").and_then(Value::as_str);
    let mut absent = false;
    for p in [field, c.get("ref").and_then(Value::as_str)].into_iter().flatten() {
        if !p.is_empty() && Ctx::new(ctx).resolve(p).is_none() {
            out.insert(p.to_string());
            absent = true;
        }
    }
    if let Some(f) = field.filter(|f| *f == "action.params" || f.starts_with("action.params.")) {
        if !matches!(ctx.get("action").and_then(|a| a.get("params")), Some(Value::Object(_) | Value::Array(_))) {
            out.insert(f.to_string());
            absent = true;
        }
    }
    if !absent {
        *ill = true;
    }
}

fn deny(reason: String, missing: Vec<MissingContext>) -> TypedDecision {
    TypedDecision { decision: "deny", reason: Some(reason), missing }
}

/// Decide a permit condition list (implicit AND) over `bound` plus whatever the request `supplied` (`Null` = nothing).
/// `bound` must be an object with an `action` object (else `bad_context`); `suppliers` `None` = the empty table.
pub fn decide_with_missing(where_: &Value, bound: &Value, supplied: &Value, suppliers: Option<&Value>) -> TypedDecision {
    if !bound.get("action").is_some_and(Value::is_object) || !bound.is_object() {
        return deny("bad_context".into(), vec![]);
    }
    let empty = Value::Object(Map::new());
    let raw = match suppliers {
        None | Some(Value::Null) => &empty,
        Some(t) => t,
    };
    if let Some(te) = supplier_table_error(raw) {
        return deny(format!("bad supplier table: {te}"), vec![]);
    }
    let table = supplier_table(raw);
    let Some(list) = where_.as_array().filter(|l| !l.is_empty()) else { return deny("condition_false".into(), vec![]) };
    let b = bind_context(bound, supplied, &table);
    if !b.conflicts.is_empty() {
        return deny(format!("context_shadow: {}", b.conflicts.join(",")), vec![]);
    }
    match evaluate_condition_tri(&json!({ "all_of": list }), &Ctx::new(&b.context)) {
        Tri::True => return TypedDecision { decision: "allow", reason: None, missing: vec![] },
        Tri::False => return deny("condition_false".into(), vec![]),
        Tri::Unknown => {}
    }
    let mut set = HashSet::new();
    let mut ill = false;
    for c in list {
        collect(c, &b.context, &mut set, &mut ill, 0);
    }
    if set.is_empty() || ill {
        return deny("ill_typed_context".into(), vec![]);
    }
    let mut paths: Vec<String> = set.into_iter().collect();
    paths.sort_by(|a, b| u16_cmp(a, b));
    let missing: Vec<MissingContext> = paths.into_iter().map(|p| MissingContext { supplier: supplier_of(&p, &table).to_string(), path: p }).collect();
    let untrusted: Vec<&str> = missing.iter().filter(|m| m.supplier == "agent_declared_untrusted").map(|m| m.path.as_str()).collect();
    if !untrusted.is_empty() {
        return deny(format!("missing_context_untrusted: {}", untrusted.join(",")), missing.clone());
    }
    let typed: Vec<String> = missing.iter().map(|m| format!("{}:{}", m.supplier, m.path)).collect();
    TypedDecision { decision: "escalate", reason: Some(format!("escalate: missing_context {}", typed.join(","))), missing }
}
