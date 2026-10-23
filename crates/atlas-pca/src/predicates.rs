//! Faithful port of `packages/pca/src/predicates.ts` (`evaluatePredicates`), the FULL non-code predicate DSL, shared with
//! the zkVM guest port. The Intent Layer v2 `layers` check evaluates the org / site / std ceilings with it (the ONE
//! predicate evaluator of the reference). Every function is total and fails CLOSED on anything malformed.
//!
//! Conditions are evaluated THREE-VALUED exactly as `evaluateConditionTri` / `triLeaf`
//! (`true` / `false` / `unknown`), so `not` / `any_of` / `all_of` groupings get the TS verdict, and every optional
//! field is typed as the TS reads it: a PRESENT `ref` of any type (including `null`) is a path that must resolve
//! (R6-ZK-01), an object with any of `all_of` / `any_of` / `not` is a group whatever other keys it carries (R6-ZK-02),
//! `action.params` is "present" when it is any object or array (R6-ZK-05).
//!
//! Operators: eq, ne, in, nin, lt, lte, gt, gte, prefix, exists, like, matches, is_a, member_of; groups all_of,
//! any_of, not. Resource matchers: exact, `*`, trailing-`*` prefix, and `re:<pattern>` (full-match regex).
//! The `re:` matcher and `matches` use a port of the TS linear-time NFA matcher (`safe_regex.rs`, R4-02): the same
//! subset guard, the same JavaScript semantics over UTF-16 code units, the same 200-unit source cap and
//! 512-unit subject cap, the same work budget.

use serde_json::{Map, Value};

/// Longest resource string a `re:` pattern is evaluated against (predicates.ts `MAX_RE_RESOURCE_LEN`).
pub const MAX_RE_RESOURCE_LEN: usize = 512;
const MAX_RE_SRC_LEN: usize = 200;
/// `MAX_MATCHES_PATTERN_LEN` / `MAX_PATTERN_SUBJECT_LEN` / `MAX_LIKE_PATTERN_LEN` (predicates.ts).
pub const MAX_MATCHES_PATTERN_LEN: usize = 200;
pub const MAX_PATTERN_SUBJECT_LEN: usize = 512;
pub const MAX_LIKE_PATTERN_LEN: usize = 512;
/// `MAX_MEMBER_CLOSURE_NODES` (predicates.ts).
pub const MAX_MEMBER_CLOSURE_NODES: usize = 10_000;

const FORBIDDEN: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// The predicate context `{action, subject?, env?}` as one JSON object with those roots. Every member is a JSON value
/// (the reference's context objects carry no `undefined` members on the paths this crate builds).
pub struct Ctx<'a> {
    pub root: &'a Value,
}

impl<'a> Ctx<'a> {
    pub fn new(root: &'a Value) -> Self {
        Ctx { root }
    }

    /// `resolvePath`: dotted path rooted at action|subject|env; own properties only; numeric array
    /// indices; forbidden keys and unknown roots => not found.
    fn resolve(&self, path: &str) -> Option<&'a Value> {
        if path.is_empty() {
            return None;
        }
        let mut segs = path.split('.');
        let root = segs.next()?;
        if !matches!(root, "action" | "subject" | "env") {
            return None;
        }
        let mut cur: &'a Value = self.root.get(root)?;
        for s in segs {
            if FORBIDDEN.contains(&s) {
                return None;
            }
            match cur {
                Value::Array(arr) => {
                    // index must be a canonical non-negative integer with no leading zeros
                    if !is_array_index(s) {
                        return None;
                    }
                    let idx: usize = s.parse().ok()?;
                    cur = arr.get(idx)?;
                }
                Value::Object(map) => {
                    cur = map.get(s)?;
                }
                _ => return None,
            }
        }
        Some(cur)
    }

    /// `deepEq` (`canonicalize(a) === canonicalize(b)`, false when either throws).
    fn deep_eq(&self, a: &Value, b: &Value) -> bool {
        js_canonical_eq(a, b)
    }
}

fn is_array_index(s: &str) -> bool {
    if s == "0" {
        return true;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if ('1'..='9').contains(&c) => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_digit())
}

/// Equality of the lenient canonical forms (`canonicalize` in hash.ts) of two parsed JSON values: numbers compare as
/// the IEEE doubles a `JSON.parse` yields (so `1 == 1.0`, `0 == -0`, and two integers beyond 2^53 that round to the
/// same double are equal), objects by key set and values, arrays element-wise.
pub fn js_canonical_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(p), Some(q)) => p == q,
            _ => false,
        },
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| js_canonical_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| js_canonical_eq(v, w)))
        }
        _ => false,
    }
}

/// Total order usable by lt/lte/gt/gte: Some(ordering) for finite number/number or string/string, else None.
fn ordered(a: &Value, b: &Value) -> Option<core::cmp::Ordering> {
    if let (Value::Number(x), Value::Number(y)) = (a, b) {
        let (x, y) = (x.as_f64()?, y.as_f64()?);
        if x.is_finite() && y.is_finite() {
            return x.partial_cmp(&y);
        }
        return None;
    }
    if let (Value::String(x), Value::String(y)) = (a, b) {
        // NORMATIVE order: UTF-8 bytes == code points (predicates.ts `orderUtf8`; a Rust string has no lone surrogate)
        return Some(x.as_bytes().cmp(y.as_bytes()));
    }
    None
}

/// Three-valued condition truth (predicates.ts `Tri`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tri {
    True,
    False,
    Unknown,
}
use Tri::{False as F, True as T, Unknown as U};

fn tri(b: bool) -> Tri {
    if b {
        T
    } else {
        F
    }
}

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

// ---- like (glob) ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum GlobTok {
    Lit(u16),
    One,
    Star,
}

/// `parseGlob`: `*` any run, `?` one UTF-16 unit, `\x` literal x; None on a dangling backslash; `**` collapses.
fn parse_glob(g: &[u16]) -> Option<Vec<GlobTok>> {
    let mut out: Vec<GlobTok> = Vec::new();
    let mut i = 0;
    while i < g.len() {
        let ch = g[i];
        if ch == b'\\' as u16 {
            let n = *g.get(i + 1)?;
            out.push(GlobTok::Lit(n));
            i += 1;
        } else if ch == b'*' as u16 {
            if out.last() != Some(&GlobTok::Star) {
                out.push(GlobTok::Star);
            }
        } else if ch == b'?' as u16 {
            out.push(GlobTok::One);
        } else {
            out.push(GlobTok::Lit(ch));
        }
        i += 1;
    }
    Some(out)
}

/// `globMatch`: anchored, O(|glob| x |s|), over UTF-16 code units. None on a malformed glob.
fn glob_match(glob: &[u16], s: &[u16]) -> Option<bool> {
    let toks = parse_glob(glob)?;
    let (mut ti, mut si) = (0usize, 0usize);
    let mut star_ti: Option<usize> = None;
    let mut star_si = 0usize;
    while si < s.len() {
        match toks.get(ti) {
            Some(GlobTok::Star) => {
                ti += 1;
                star_ti = Some(ti);
                star_si = si;
            }
            Some(GlobTok::One) => {
                ti += 1;
                si += 1;
            }
            Some(GlobTok::Lit(c)) if s[si] == *c => {
                ti += 1;
                si += 1;
            }
            _ => match star_ti {
                Some(st) => {
                    ti = st;
                    star_si += 1;
                    si = star_si;
                }
                None => return Some(false),
            },
        }
    }
    while toks.get(ti) == Some(&GlobTok::Star) {
        ti += 1;
    }
    Some(ti == toks.len())
}

// ---- is_a / member_of ---------------------------------------------------------------------------------------

/// `typeTagMatch`: None when the value carries no decidable type/tag.
fn type_tag_match(v: &Value, t: &str) -> Option<bool> {
    let tp = format!("{t}::");
    let tagged = |s: &str| s == t || s.starts_with(tp.as_str());
    match v {
        Value::String(s) => Some(tagged(s)),
        Value::Object(o) => {
            let mut decidable = false;
            let mut matched = false;
            if let Some(Value::String(ty)) = o.get("type") {
                decidable = true;
                if tagged(ty) {
                    matched = true;
                }
            }
            if let Some(Value::Array(tags)) = o.get("tags") {
                decidable = true;
                if tags.iter().any(|x| x.as_str() == Some(t)) {
                    matched = true;
                }
            }
            decidable.then_some(matched)
        }
        _ => None,
    }
}

fn neighbours_of<'v>(adj: &'v Map<String, Value>, node: &str) -> Vec<&'v str> {
    if FORBIDDEN.contains(&node) {
        return Vec::new();
    }
    match adj.get(node) {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect(),
        _ => Vec::new(),
    }
}

/// `memberClosure`: reflexive, bounded (`MAX_MEMBER_CLOSURE_NODES` dequeues), cycle-guarded BFS.
fn member_closure<'v>(start: &'v str, adj: &'v Map<String, Value>) -> std::collections::BTreeSet<&'v str> {
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(start);
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(start);
    let mut visited = 0usize;
    while visited < MAX_MEMBER_CLOSURE_NODES {
        let node = match queue.pop_front() {
            Some(n) => n,
            None => break,
        };
        visited += 1;
        for n in neighbours_of(adj, node) {
            if seen.insert(n) {
                queue.push_back(n);
            }
        }
    }
    seen
}

// ---- leaf + groups --------------------------------------------------------------------------------------------

fn params_present(ctx: &Ctx) -> bool {
    // TS: `p === undefined || p === null || typeof p !== 'object'` => unavailable; arrays ARE objects there.
    matches!(ctx.root.get("action").and_then(|a| a.get("params")), Some(Value::Object(_)) | Some(Value::Array(_)))
}

fn params_rooted(path: &str) -> bool {
    path == "action.params" || path.starts_with("action.params.")
}

/// Resolve the operand (`ref` when the key is PRESENT, whatever its type; else `value` when present). None = unknown.
fn operand<'a>(c: &Map<String, Value>, ctx: &Ctx<'a>) -> Option<OperandRef<'a>> {
    match c.get("ref") {
        Some(Value::String(r)) => ctx.resolve(r).map(OperandRef::Ctx),
        Some(_) => None, // R6-ZK-01: `resolvePath` of a non-string path is not found => unknown
        None => c.get("value").cloned().map(OperandRef::Lit),
    }
}

enum OperandRef<'a> {
    Ctx(&'a Value),
    Lit(Value),
}
impl OperandRef<'_> {
    fn v(&self) -> &Value {
        match self {
            OperandRef::Ctx(v) => v,
            OperandRef::Lit(v) => v,
        }
    }
}

/// predicates.ts `triLeaf`.
fn tri_leaf(c: &Map<String, Value>, ctx: &Ctx) -> Tri {
    let field = match c.get("field") {
        Some(Value::String(s)) if !s.is_empty() => s.as_str(),
        _ => return U,
    };
    let op = match c.get("op") {
        Some(Value::String(s)) => s.as_str(),
        _ => return U,
    };
    if params_rooted(field) && !params_present(ctx) {
        return U;
    }
    if let Some(Value::String(r)) = c.get("ref") {
        if params_rooted(r) && !params_present(ctx) {
            return U;
        }
    }
    let f = ctx.resolve(field);
    if op == "exists" {
        let want_absent = matches!(c.get("value"), Some(Value::Bool(false)));
        return tri(if want_absent { f.is_none() } else { f.is_some() });
    }
    let v = match f {
        Some(v) => v,
        None => return U,
    };

    if op == "member_of" {
        let start = match v {
            Value::String(s) => s.as_str(),
            _ => return U,
        };
        let coll = match c.get("collection") {
            Some(Value::String(s)) if !s.is_empty() => s.as_str(),
            _ => return U,
        };
        let adj = match ctx.resolve(coll) {
            Some(Value::Object(m)) => m,
            _ => return U,
        };
        let target = match operand(c, ctx) {
            Some(o) => o,
            None => return U,
        };
        let targets: Vec<&str> = match target.v() {
            Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect(),
            Value::String(s) => vec![s.as_str()],
            _ => Vec::new(),
        };
        if targets.is_empty() {
            return U;
        }
        let reach = member_closure(start, adj);
        return tri(targets.iter().any(|t| reach.contains(t)));
    }

    let operand = match operand(c, ctx) {
        Some(o) => o,
        None => return U,
    };
    let o = operand.v();

    match op {
        "eq" => tri(ctx.deep_eq(v, o)),
        "ne" => tri(!ctx.deep_eq(v, o)),
        "in" => match o {
            Value::Array(arr) => tri(arr.iter().any(|x| ctx.deep_eq(v, x))),
            _ => U,
        },
        "nin" => match o {
            Value::Array(arr) => tri(!arr.iter().any(|x| ctx.deep_eq(v, x))),
            _ => U,
        },
        "lt" | "lte" | "gt" | "gte" => match ordered(v, o) {
            None => U,
            Some(ord) => {
                use core::cmp::Ordering::*;
                tri(match op {
                    "lt" => ord == Less,
                    "lte" => ord != Greater,
                    "gt" => ord == Greater,
                    _ => ord != Less,
                })
            }
        },
        "prefix" => match (v, o) {
            (Value::String(s), Value::String(p)) => tri(s.starts_with(p.as_str())),
            _ => U,
        },
        "like" => match (v, o) {
            (Value::String(s), Value::String(g)) => {
                let (s, g) = (utf16(s), utf16(g));
                if g.len() > MAX_LIKE_PATTERN_LEN || s.len() > MAX_PATTERN_SUBJECT_LEN {
                    return U;
                }
                match glob_match(&g, &s) {
                    Some(b) => tri(b),
                    None => U,
                }
            }
            _ => U,
        },
        // R5-ZK-04: both strings, source <= 200 and subject <= 512 UTF-16 units, then `isSafeRegexSource` ->
        // `chargeRegex` (per-document budget) -> linear-time full match.
        "matches" => match (v, o) {
            (Value::String(s), Value::String(p)) => {
                if p.encode_utf16().count() > MAX_MATCHES_PATTERN_LEN || s.encode_utf16().count() > MAX_PATTERN_SUBJECT_LEN {
                    return U;
                }
                match super::safe_regex::full_match_tri(p, s) {
                    Some(b) => tri(b),
                    None => U,
                }
            }
            _ => U,
        },
        "is_a" => match o {
            Value::String(t) if !t.is_empty() => match type_tag_match(v, t) {
                Some(b) => tri(b),
                None => U,
            },
            _ => U,
        },
        _ => U,
    }
}

/// `isGroupCondition`: an object carrying ANY of `all_of` / `any_of` / `not` (whatever other keys it has).
pub fn is_group_condition(c: &Value) -> bool {
    match c {
        Value::Object(o) => o.contains_key("all_of") || o.contains_key("any_of") || o.contains_key("not"),
        _ => false,
    }
}

/// predicates.ts `evaluateConditionTri`.
pub fn evaluate_condition_tri(c: &Value, ctx: &Ctx) -> Tri {
    super::safe_regex::with_regex_budget(|| evaluate_condition_tri_inner(c, ctx))
}

fn evaluate_condition_tri_inner(c: &Value, ctx: &Ctx) -> Tri {
    let o = match c {
        Value::Object(o) => o,
        _ => return U, // null, scalars and arrays (an array is not a group and has no string `field`)
    };
    if is_group_condition(c) {
        if let Some(all) = o.get("all_of") {
            let arr = match all {
                Value::Array(a) if !a.is_empty() => a,
                _ => return U,
            };
            let mut saw_unknown = false;
            for x in arr {
                match evaluate_condition_tri(x, ctx) {
                    F => return F,
                    U => saw_unknown = true,
                    T => {}
                }
            }
            return if saw_unknown { U } else { T };
        }
        if let Some(any) = o.get("any_of") {
            let arr = match any {
                Value::Array(a) if !a.is_empty() => a,
                _ => return U,
            };
            let mut saw_unknown = false;
            for x in arr {
                match evaluate_condition_tri(x, ctx) {
                    T => return T,
                    U => saw_unknown = true,
                    F => {}
                }
            }
            return if saw_unknown { U } else { F };
        }
        // 'not'
        let inner = match o.get("not") {
            Some(n) => evaluate_condition_tri(n, ctx),
            None => U,
        };
        return match inner {
            T => F,
            F => T,
            U => U,
        };
    }
    tri_leaf(o, ctx)
}

/// `evaluateCondition`: `evaluateConditionTri(c) === 'true'`.
pub fn evaluate_condition(c: &Value, ctx: &Ctx) -> bool {
    evaluate_condition_tri(c, ctx) == T
}

fn verb_matches(pverb: &Value, verb: &str) -> bool {
    match pverb {
        Value::String(s) => s == "*" || s == verb,
        Value::Array(arr) => arr
            .iter()
            .any(|x| matches!(x.as_str(), Some(s) if s == "*" || s == verb)),
        _ => false,
    }
}

fn resource_matches(pattern: Option<&Value>, resource: &str) -> bool {
    let pat = match pattern {
        None => return true, // omitted = any resource
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return false,
    };
    if pat == "*" {
        return true;
    }
    if let Some(src) = pat.strip_prefix("re:") {
        // lengths are UTF-16 code units, as in JavaScript (`String.prototype.length`)
        if src.encode_utf16().count() > MAX_RE_SRC_LEN {
            return false;
        }
        if resource.encode_utf16().count() > MAX_RE_RESOURCE_LEN {
            return false;
        }
        // R4-02: the SAME linear-time matcher as the TS reference (`isSafeRegexSource` + `safeRegexFullMatch`), ported in
        // `safe_regex.rs`; a pattern outside its subset, or over the work budget, does not match.
        return super::safe_regex::full_match(src, resource);
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    pat == resource
}

/// Does a single predicate permit the action? (predicates.ts `predicateMatches`)
pub fn predicate_matches(p: &Value, ctx: &Ctx) -> bool {
    super::safe_regex::with_regex_budget(|| predicate_matches_inner(p, ctx))
}

fn predicate_matches_inner(p: &Value, ctx: &Ctx) -> bool {
    // TS: `p === null || typeof p !== 'object'` => false; an ARRAY passes that test but has no `verb`, so is false too.
    let obj = match p.as_object() {
        Some(o) => o,
        None => return false,
    };
    let action = match ctx.root.get("action") {
        Some(a) => a,
        None => return false,
    };
    let verb = match action.get("verb").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return false,
    };
    let resource = match action.get("resource").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => return false,
    };
    let pverb = match obj.get("verb") {
        Some(v) => v,
        None => return false,
    };
    if !verb_matches(pverb, verb) {
        return false;
    }
    if !resource_matches(obj.get("resource"), resource) {
        return false;
    }
    if let Some(where_clause) = obj.get("where") {
        let arr = match where_clause.as_array() {
            Some(a) => a,
            None => return false,
        };
        for cv in arr {
            if !evaluate_condition(cv, ctx) {
                return false;
            }
        }
    }
    true
}

/// `evaluatePredicates(predicates, ctx).allowed`: the action is allowed iff it matches at least one predicate (verb AND
/// resource AND every `where`). Default-deny: an empty list allows nothing.
pub fn evaluate_predicates(predicates: &[Value], ctx: &Ctx) -> bool {
    super::safe_regex::with_regex_budget(|| predicates.iter().any(|p| predicate_matches(p, ctx)))
}

#[cfg(test)]
#[path = "k042_predicates_test.rs"]
mod k042_test;
