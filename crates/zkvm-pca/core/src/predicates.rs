//! Faithful port of `packages/pca/src/predicates.ts` — the FULL, non-code predicate DSL.
//!
//! This is the headline of the zkVM path: the WHOLE DSL runs natively inside the guest, with NO
//! reduction to a boolean (as the circom/Winterfell circuits were forced to do). Every function is
//! total and fails CLOSED (condition false / predicate not matched) on anything malformed.
//!
//! Operators: eq, ne, in, nin, lt, lte, gt, gte, prefix, exists.
//! Resource matchers: exact, `*`, trailing-`*` prefix, and `re:<pattern>` (full-match regex).
//! The `re:` matcher uses the `regex` crate, which is linear-time by construction (no catastrophic
//! backtracking), so it provides the same ReDoS safety the hand-rolled `isSafeRegexSource` subset
//! check gives in TS, with the same 200-char source cap and 512-char subject cap.

use crate::canonical::canonicalize;
use serde_json::Value;

/// Longest resource string a `re:` pattern is evaluated against (predicates.ts `MAX_RE_RESOURCE_LEN`).
pub const MAX_RE_RESOURCE_LEN: usize = 512;
const MAX_RE_SRC_LEN: usize = 200;

const FORBIDDEN: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// The action/subject/env context, carried as a single JSON object with those three roots.
pub struct Ctx<'a> {
    pub root: &'a Value,
}

impl<'a> Ctx<'a> {
    pub fn new(root: &'a Value) -> Self {
        Ctx { root }
    }

    /// `resolvePath`: dotted path rooted at action|subject|env; own properties only; numeric array
    /// indices; forbidden keys and unknown roots => not found.
    fn resolve(&self, path: &str) -> Option<&Value> {
        if path.is_empty() {
            return None;
        }
        let mut segs = path.split('.');
        let root = segs.next()?;
        if !matches!(root, "action" | "subject" | "env") {
            return None;
        }
        let mut cur = self.root.get(root)?;
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

fn deep_eq(a: &Value, b: &Value) -> bool {
    canonicalize(a) == canonicalize(b)
}

/// Total order usable by lt/lte/gt/gte: Some(ordering) for number/number or string/string, else None.
fn ordered(a: &Value, b: &Value) -> Option<core::cmp::Ordering> {
    if let (Some(x), Some(y)) = (a.as_f64(), b.as_f64()) {
        if x.is_finite() && y.is_finite() {
            return x.partial_cmp(&y);
        }
        return None;
    }
    if let (Value::String(x), Value::String(y)) = (a, b) {
        // bytewise UTF-8 comparison (matches TS `a < b` on strings for the BMP; both use code-unit order)
        return Some(x.as_bytes().cmp(y.as_bytes()));
    }
    None
}

#[derive(Clone)]
pub struct Condition {
    pub field: String,
    pub op: String,
    pub value: Option<Value>,
    pub has_value_key: bool,
    pub reference: Option<String>,
}

impl Condition {
    fn from_value(v: &Value) -> Option<Condition> {
        let obj = v.as_object()?;
        let field = obj.get("field").and_then(|x| x.as_str())?.to_string();
        let op = obj.get("op").and_then(|x| x.as_str())?.to_string();
        let has_value_key = obj.contains_key("value");
        let value = obj.get("value").cloned();
        let reference = obj.get("ref").and_then(|x| x.as_str()).map(|s| s.to_string());
        Some(Condition {
            field,
            op,
            value,
            has_value_key,
            reference,
        })
    }
}

/// Evaluate one condition (predicates.ts `evaluateCondition`). Missing field/operand => false
/// (except `exists:false`); unknown op => false. `action.params*` with unavailable params => false.
pub fn evaluate_condition(c: &Condition, ctx: &Ctx) -> bool {
    // "params unavailable" is NOT "field absent": a params-rooted condition must fail closed.
    if c.field == "action.params" || c.field.starts_with("action.params.") {
        if !params_present(ctx) {
            return false;
        }
    }
    if let Some(r) = &c.reference {
        if r == "action.params" || r.starts_with("action.params.") {
            if !params_present(ctx) {
                return false;
            }
        }
    }

    let f = ctx.resolve(&c.field);

    if c.op == "exists" {
        return match &c.value {
            Some(Value::Bool(false)) => f.is_none(),
            _ => f.is_some(),
        };
    }

    let fv = match f {
        Some(v) => v,
        None => return false,
    };

    // operand resolution
    let operand: Value = if let Some(r) = &c.reference {
        match ctx.resolve(r) {
            Some(v) => v.clone(),
            None => return false,
        }
    } else {
        match (c.has_value_key, &c.value) {
            (true, Some(v)) if !v.is_null() => v.clone(),
            // has_value_key && value === undefined is impossible in serde (absent => not has_value_key);
            // Value::Null means an explicit null operand, which TS treats as a present value for eq/ne.
            (true, Some(v)) => v.clone(),
            _ => return false,
        }
    };

    match c.op.as_str() {
        "eq" => deep_eq(fv, &operand),
        "ne" => !deep_eq(fv, &operand),
        "in" => operand
            .as_array()
            .map(|arr| arr.iter().any(|x| deep_eq(fv, x)))
            .unwrap_or(false),
        "nin" => operand
            .as_array()
            .map(|arr| !arr.iter().any(|x| deep_eq(fv, x)))
            .unwrap_or(false),
        "lt" => ordered(fv, &operand) == Some(core::cmp::Ordering::Less),
        "lte" => matches!(
            ordered(fv, &operand),
            Some(core::cmp::Ordering::Less) | Some(core::cmp::Ordering::Equal)
        ),
        "gt" => ordered(fv, &operand) == Some(core::cmp::Ordering::Greater),
        "gte" => matches!(
            ordered(fv, &operand),
            Some(core::cmp::Ordering::Greater) | Some(core::cmp::Ordering::Equal)
        ),
        "prefix" => match (fv.as_str(), operand.as_str()) {
            (Some(v), Some(o)) => v.starts_with(o),
            _ => false,
        },
        _ => false,
    }
}

fn params_present(ctx: &Ctx) -> bool {
    matches!(
        ctx.root.get("action").and_then(|a| a.get("params")),
        Some(Value::Object(_))
    )
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
        if src.len() > MAX_RE_SRC_LEN {
            return false;
        }
        if resource.len() > MAX_RE_RESOURCE_LEN {
            return false;
        }
        let anchored = format!("^(?:{})$", src);
        match regex::Regex::new(&anchored) {
            Ok(re) => return re.is_match(resource),
            Err(_) => return false,
        }
    }
    if let Some(prefix) = pat.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    pat == resource
}

/// Does a single predicate permit the action? (predicates.ts `predicateMatches`)
pub fn predicate_matches(p: &Value, ctx: &Ctx) -> bool {
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
            match Condition::from_value(cv) {
                Some(cond) => {
                    if !evaluate_condition(&cond, ctx) {
                        return false;
                    }
                }
                None => return false,
            }
        }
    }
    true
}

pub struct PredicateResult {
    pub allowed: bool,
    pub reason: Option<String>,
}

/// An action is allowed iff it matches at least one predicate. Default-deny on empty list.
pub fn evaluate_predicates(predicates: &[Value], ctx: &Ctx) -> PredicateResult {
    if predicates.is_empty() {
        return PredicateResult {
            allowed: false,
            reason: Some("envelope grants no predicates".to_string()),
        };
    }
    for p in predicates {
        if predicate_matches(p, ctx) {
            return PredicateResult {
                allowed: true,
                reason: None,
            };
        }
    }
    PredicateResult {
        allowed: false,
        reason: Some("no predicate permits the action".to_string()),
    }
}
