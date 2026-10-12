//! Faithful port of the caveat evaluators: the built-in envelope caveats
//! (`packages/pca/src/predicates.ts` `envelopeCaveatEvaluator`) plus the agent-native superset
//! (`agent-native.ts` `agentNativeCaveatEvaluator`): `predicates` and `tool_schema`.
//!
//! All caveats are CONJUNCTIVE and fail CLOSED (unknown/malformed type => unsatisfied). Numeric
//! threshold comparisons use `f64` COMPARISONS only (never float arithmetic in the proven gate), which
//! are deterministic (IEEE-754), matching the TS semantics byte-for-byte.

use crate::commit::hash_canonical;
use crate::predicates::{predicate_matches, Ctx};
use serde_json::{json, Value};

/// Reversibility classes in increasing severity.
const REVERSIBILITY_ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

/// Context the caveats are evaluated against.
pub struct CaveatCtx<'a> {
    pub now: f64,
    pub blast_radius: Option<f64>,
    /// `action.reversibility_class ?? node.reversibility_class` exactly as the TS `CaveatContext` carries it: any JSON
    /// type (a non-string never satisfies `reversibility_max`); `None` = undefined.
    pub reversibility_class: Option<Value>,
    pub delegation_depth: Option<f64>,
    pub recent_action_times: Option<Vec<f64>>,
    /// The action/subject/env root (for `predicates` caveats).
    pub action_root: &'a Value,
    /// The derived tool call (for `tool_schema` caveats): (tool, args, signature_digest?).
    pub tool: Option<String>,
    pub tool_args: Option<Value>,
    pub tool_signature_digest: Option<String>,
}

fn fin(v: Option<&Value>) -> Option<f64> {
    v.and_then(|x| x.as_f64()).filter(|f| f.is_finite())
}

/// Evaluate a single caveat. Total; fail closed.
pub fn evaluate_caveat(cv: &Value, ctx: &CaveatCtx) -> bool {
    let obj = match cv.as_object() {
        Some(o) => o,
        None => return false,
    };
    let ty = match obj.get("type").and_then(|t| t.as_str()) {
        Some(t) => t,
        None => return false,
    };
    if !ctx.now.is_finite() {
        // envelopeCaveatEvaluator requires a finite now for the time-based ones; the agent-native
        // `predicates`/`tool_schema` do not read `now`, so handle those before the now gate.
        match ty {
            "predicates" | "tool_schema" => {}
            _ => return false,
        }
    }
    match ty {
        "expires" => matches!(fin(obj.get("at")), Some(at) if ctx.now < at),
        "not_before" => matches!(fin(obj.get("at")), Some(at) if ctx.now >= at),
        "rate" => {
            let max = match fin(obj.get("max")) {
                Some(m) => m,
                None => return false,
            };
            let per = match fin(obj.get("per_secs")) {
                Some(p) if p > 0.0 => p,
                _ => return false,
            };
            let times = match &ctx.recent_action_times {
                Some(t) => t,
                None => return false,
            };
            let lo = ctx.now - per * 1000.0;
            let n = times
                .iter()
                .filter(|t| t.is_finite() && **t > lo && **t <= ctx.now)
                .count() as f64;
            n < max
        }
        "max_blast_radius" => match (fin(obj.get("max")), ctx.blast_radius) {
            (Some(max), Some(br)) if br.is_finite() => br <= max,
            _ => false,
        },
        "reversibility_max" => {
            // strict types on both sides (predicates.ts: `typeof caveat.class !== 'string' || typeof c.reversibilityClass
            // !== 'string'` => false)
            let lim = class_rank(obj.get("class").and_then(|c| c.as_str()));
            let cur = class_rank(ctx.reversibility_class.as_ref().and_then(|c| c.as_str()));
            matches!((lim, cur), (Some(l), Some(c)) if c <= l)
        }
        "delegation_depth" => match (fin(obj.get("max")), ctx.delegation_depth) {
            (Some(max), Some(dd)) if dd.is_finite() => dd <= max,
            _ => false,
        },
        "budget_alloc" => matches!(fin(obj.get("limit")), Some(l) if l >= 0.0),
        "predicates" => {
            let allow = match obj.get("allow").and_then(|a| a.as_array()) {
                Some(a) => a,
                None => return false,
            };
            let c = Ctx::new(ctx.action_root);
            allow.iter().any(|p| predicate_matches(p, &c))
        }
        "tool_schema" => evaluate_tool_schema(obj, ctx).is_ok(),
        _ => false,
    }
}

fn class_rank(c: Option<&str>) -> Option<usize> {
    c.and_then(|s| REVERSIBILITY_ORDER.iter().position(|&x| x == s))
}

pub struct CaveatOutcome {
    pub ok: bool,
    pub failed: Vec<String>,
}

/// Evaluate all caveats; ok iff every one is satisfied.
pub fn evaluate_caveats(caveats: &[Value], ctx: &CaveatCtx) -> CaveatOutcome {
    crate::safe_regex::with_regex_budget(|| evaluate_caveats_inner(caveats, ctx))
}

fn evaluate_caveats_inner(caveats: &[Value], ctx: &CaveatCtx) -> CaveatOutcome {
    let mut failed = Vec::new();
    for cv in caveats {
        if !evaluate_caveat(cv, ctx) {
            let ty = cv
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("<malformed>")
                .to_string();
            failed.push(ty);
        }
    }
    CaveatOutcome {
        ok: failed.is_empty(),
        failed,
    }
}

// ---- tool_schema (agent-native.ts evaluateToolSchema) --------------------------------------------

const MAX_SCHEMA_DEPTH: usize = 8;
const MAX_SCHEMA_NODES: usize = 256;
const MAX_OBJECT_PROPS: usize = 64;
const MAX_ENUM_VALUES: usize = 256;
const DEFAULT_MAX_ARRAY_ITEMS: usize = 256;
const ABSOLUTE_MAX_ARRAY_ITEMS: usize = 4096;
const DEFAULT_MAX_STRING_LEN: usize = 65_536;
const ABSOLUTE_MAX_STRING_LEN: usize = 1_048_576;
const MAX_VALUE_NODES: usize = 10_000;

fn is_safe_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// R4-03: `Ok(())` ONLY when the caveat is well-formed, self-consistent, bound to the call and the call satisfies the
/// schema; EVERY other outcome (a missing or mistyped field, a digest that is absent or wrong, no call context, an
/// argument violation) is `Err`. The previous version returned `Option<String>` with `None` = satisfied and used `?` on
/// `Option` for the field lookups, so each absent field silently meant "satisfied" (agent-native.ts fails closed).
fn evaluate_tool_schema(cv: &serde_json::Map<String, Value>, ctx: &CaveatCtx) -> Result<(), String> {
    let missing = |what: &str| format!("malformed tool_schema caveat: {what}");
    let tool = match cv.get("tool").and_then(|t| t.as_str()).filter(|s| !s.is_empty()) {
        Some(t) => t,
        None => return Err(missing("tool")),
    };
    let schema = match cv.get("schema") {
        Some(s) => s,
        None => return Err(missing("schema")),
    };
    if let Some(e) = validate_arg_schema(schema) {
        return Err(e);
    }
    // `hashCanonical(schema)` THROWS in the TS reference outside the strict profile (fail closed).
    if crate::canonical::strict_violation(schema).is_some() {
        return Err("schema outside the strict canonical profile".to_string());
    }
    // self-consistency: schema_digest + binding_digest, both mandatory strings
    let schema_digest = match cv.get("schema_digest").and_then(|d| d.as_str()) {
        Some(d) => d,
        None => return Err(missing("schema_digest")),
    };
    if hash_canonical(schema) != schema_digest {
        return Err("schema digest mismatch".to_string());
    }
    // R6-ZK-05: the TS binds `String(caveat.signature_digest)` (so a number, `null`, an array or even an ABSENT digest
    // is hashed as its JavaScript string form) and compares the signed `tool_binding` with `!==` against the raw value.
    let sig_digest_raw = cv.get("signature_digest");
    let sig_digest = crate::canonical::js_string(sig_digest_raw);
    let binding = json!({ "tool": tool, "signature_digest": sig_digest, "schema": schema });
    let binding_digest = match cv.get("binding_digest").and_then(|d| d.as_str()) {
        Some(d) => d,
        None => return Err(missing("binding_digest")),
    };
    if hash_canonical(&binding) != binding_digest {
        return Err("binding digest mismatch".to_string());
    }

    // the call: a tool name and an argument object are both required
    let call_tool = match ctx.tool.as_deref() {
        Some(t) => t,
        None => return Err("malformed call".to_string()),
    };
    let args = match &ctx.tool_args {
        Some(a @ Value::Object(_)) => a,
        _ => return Err("malformed call".to_string()),
    };
    if call_tool != tool {
        return Err("tool not authorized".to_string());
    }
    if let Some(d) = &ctx.tool_signature_digest {
        if sig_digest_raw.and_then(|x| x.as_str()) != Some(d.as_str()) {
            return Err("signed tool_binding differs from the authorized tool signature".to_string());
        }
    }

    let props = match schema.get("props") {
        Some(p) => p,
        None => return Err(missing("schema.props")),
    };
    let required = schema.get("required");
    match check_object(props, required, args, 1, &mut 0usize) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn validate_arg_schema(schema: &Value) -> Option<String> {
    let obj = match schema.as_object() {
        Some(o) => o,
        None => return Some("schema must be an object".to_string()),
    };
    for k in obj.keys() {
        if k != "props" && k != "required" {
            return Some("unknown schema key".to_string());
        }
    }
    let mut nodes = 0usize;
    object_schema_error(obj.get("props"), obj.get("required"), 1, &mut nodes)
}

fn object_schema_error(
    props: Option<&Value>,
    required: Option<&Value>,
    depth: usize,
    nodes: &mut usize,
) -> Option<String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Some("schema too deep".to_string());
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Some("schema too large".to_string());
    }
    let props = match props.and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return Some("props must be an object".to_string()),
    };
    if props.len() > MAX_OBJECT_PROPS {
        return Some("too many props".to_string());
    }
    for (n, spec) in props.iter() {
        if !is_safe_name(n) {
            return Some("invalid property name".to_string());
        }
        if let Some(e) = spec_error(spec, depth + 1, nodes) {
            return Some(e);
        }
    }
    if let Some(req) = required {
        let arr = match req.as_array() {
            Some(a) if a.len() <= MAX_OBJECT_PROPS => a,
            _ => return Some("required must be a short array".to_string()),
        };
        for r in arr {
            match r.as_str() {
                Some(name) if props.contains_key(name) => {}
                _ => return Some("required names an undeclared property".to_string()),
            }
        }
    }
    None
}

fn spec_error(spec: &Value, depth: usize, nodes: &mut usize) -> Option<String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Some("schema too deep".to_string());
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Some("schema too large".to_string());
    }
    let obj = match spec.as_object() {
        Some(o) => o,
        None => return Some("unknown type".to_string()),
    };
    let t = match obj.get("type").and_then(|x| x.as_str()) {
        Some(t) => t,
        None => return Some("unknown type".to_string()),
    };
    let allowed: &[&str] = match t {
        "string" => &["type", "enum", "const", "minLength", "maxLength", "prefix"],
        "number" | "integer" => &["type", "enum", "const", "min", "max"],
        "boolean" => &["type", "enum", "const"],
        "object" => &["type", "props", "required"],
        "array" => &["type", "items", "minItems", "maxItems"],
        _ => return Some("unknown type".to_string()),
    };
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return Some("unknown spec key".to_string());
        }
    }
    if t == "object" {
        *nodes -= 1; // counted by object_schema_error
        return object_schema_error(obj.get("props"), obj.get("required"), depth, nodes);
    }
    if t == "array" {
        // R5-ZK-01: every bound is read as a JavaScript number (`fin && Number.isInteger && 0 <= x <= max`); a present but
        // malformed bound is an ERROR, never a default.
        let mi = obj.get("minItems");
        let ma = obj.get("maxItems");
        if let Some(mi) = mi {
            if non_neg_int(mi, ABSOLUTE_MAX_ARRAY_ITEMS as f64).is_none() {
                return Some("bad minItems".to_string());
            }
        }
        if let Some(ma) = ma {
            if non_neg_int(ma, ABSOLUTE_MAX_ARRAY_ITEMS as f64).is_none() {
                return Some("bad maxItems".to_string());
            }
        }
        if let (Some(mi), Some(ma)) = (mi.and_then(fin_num), ma.and_then(fin_num)) {
            if mi > ma {
                return Some("minItems > maxItems".to_string());
            }
        }
        return match obj.get("items") {
            Some(items) => spec_error(items, depth + 1, nodes),
            None => Some("unknown type".to_string()),
        };
    }
    // scalars: enum/const type checks (UTF-16 lengths, JS number semantics)
    let ok = |v: &Value| -> bool {
        match t {
            "string" => v.as_str().map(|s| utf16_len(s) <= 1024).unwrap_or(false),
            "boolean" => v.is_boolean(),
            "number" => fin_num(v).is_some(),
            "integer" => fin_num(v).map(|f| f.fract() == 0.0).unwrap_or(false),
            _ => false,
        }
    };
    if let Some(c) = obj.get("const") {
        if !ok(c) {
            return Some("bad const".to_string());
        }
    }
    if let Some(e) = obj.get("enum") {
        match e.as_array() {
            Some(a) if !a.is_empty() && a.len() <= MAX_ENUM_VALUES && a.iter().all(ok) => {}
            _ => return Some("bad enum".to_string()),
        }
    }
    if t == "string" {
        let mn = obj.get("minLength");
        let mx = obj.get("maxLength");
        if let Some(v) = mn {
            if non_neg_int(v, ABSOLUTE_MAX_STRING_LEN as f64).is_none() {
                return Some("bad minLength".to_string());
            }
        }
        if let Some(v) = mx {
            if non_neg_int(v, ABSOLUTE_MAX_STRING_LEN as f64).is_none() {
                return Some("bad maxLength".to_string());
            }
        }
        if let (Some(a), Some(b)) = (mn.and_then(fin_num), mx.and_then(fin_num)) {
            if a > b {
                return Some("minLength > maxLength".to_string());
            }
        }
        if let Some(p) = obj.get("prefix") {
            match p.as_str() {
                Some(p) if utf16_len(p) <= 512 => {}
                _ => return Some("bad prefix".to_string()),
            }
        }
    } else if t == "number" || t == "integer" {
        let mn = obj.get("min");
        let mx = obj.get("max");
        if let Some(v) = mn {
            if fin_num(v).is_none() {
                return Some("bad min".to_string());
            }
        }
        if let Some(v) = mx {
            if fin_num(v).is_none() {
                return Some("bad max".to_string());
            }
        }
        if let (Some(a), Some(b)) = (mn.and_then(fin_num), mx.and_then(fin_num)) {
            if a > b {
                return Some("min > max".to_string());
            }
        }
    }
    None
}

/// JavaScript `String.prototype.length` (UTF-16 code units). R5-ZK-02.
fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `fin(x)`: a JSON number that is a finite double (the value a `JSON.parse` would give).
fn fin_num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64().filter(|f| f.is_finite()),
        _ => None,
    }
}

/// `nonNegInt(x, max)`: finite, integral, `0 <= x <= max`.
fn non_neg_int(v: &Value, max: f64) -> Option<f64> {
    fin_num(v).filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f <= max)
}

/// JavaScript `===` on two scalars (number by value, so `1 === 1.0` and `0 === -0`).
fn scalar_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(_), Value::Number(_)) => match (fin_num(a), fin_num(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        _ => false,
    }
}

fn check_object(
    props: &Value,
    required: Option<&Value>,
    obj: &Value,
    depth: usize,
    budget: &mut usize,
) -> Option<String> {
    let props = match props.as_object() {
        Some(p) => p,
        None => return Some("malformed schema: props".to_string()),
    };
    let map = match obj.as_object() {
        Some(m) => m,
        None => return Some("malformed call: arguments".to_string()),
    };
    for k in map.keys() {
        if !props.contains_key(k) {
            return Some(format!("unexpected argument {}", k));
        }
    }
    if let Some(req) = required {
        let arr = match req.as_array() {
            Some(a) => a,
            None => return Some("malformed schema: required".to_string()),
        };
        for r in arr {
            match r.as_str() {
                Some(name) => {
                    if !map.contains_key(name) {
                        return Some(format!("missing required argument '{}'", name));
                    }
                }
                None => return Some("malformed schema: required".to_string()),
            }
        }
    }
    for (k, v) in map.iter() {
        let spec = match props.get(k) {
            Some(s) => s,
            None => return Some(format!("unexpected argument {}", k)),
        };
        if let Some(e) = check_value(spec, v, depth + 1, budget) {
            return Some(e);
        }
    }
    None
}

fn check_value(spec: &Value, v: &Value, depth: usize, budget: &mut usize) -> Option<String> {
    if depth > MAX_SCHEMA_DEPTH + 1 {
        return Some("too deep".to_string());
    }
    *budget += 1;
    if *budget > MAX_VALUE_NODES {
        return Some("too many values".to_string());
    }
    let obj = match spec.as_object() {
        Some(o) => o,
        None => return Some("malformed schema: spec".to_string()),
    };
    let t = match obj.get("type").and_then(|x| x.as_str()) {
        Some(t) => t,
        None => return Some("malformed schema: type".to_string()),
    };
    match t {
        "object" => {
            if !v.is_object() {
                return Some("expected object".to_string());
            }
            let props = match obj.get("props") {
                Some(p) => p,
                None => return Some("malformed schema: props".to_string()),
            };
            return check_object(props, obj.get("required"), v, depth, budget);
        }
        "array" => {
            let arr = match v.as_array() {
                Some(a) => a,
                None => return Some("expected array".to_string()),
            };
            // R5-ZK-01: a malformed bound DENIES (the schema is validated first; this is the second line of defence).
            let max = match obj.get("maxItems") {
                None => DEFAULT_MAX_ARRAY_ITEMS,
                Some(m) => match non_neg_int(m, ABSOLUTE_MAX_ARRAY_ITEMS as f64) {
                    Some(m) => m as usize,
                    None => return Some("malformed schema: maxItems".to_string()),
                },
            };
            if arr.len() > max {
                return Some("exceeds maxItems".to_string());
            }
            if let Some(mi) = obj.get("minItems") {
                match non_neg_int(mi, ABSOLUTE_MAX_ARRAY_ITEMS as f64) {
                    Some(mi) if (arr.len() as f64) < mi => return Some("below minItems".to_string()),
                    Some(_) => {}
                    None => return Some("malformed schema: minItems".to_string()),
                }
            }
            let items = match obj.get("items") {
                Some(i) => i,
                None => return Some("malformed schema: items".to_string()),
            };
            for item in arr {
                if let Some(e) = check_value(items, item, depth + 1, budget) {
                    return Some(e);
                }
            }
            return None;
        }
        "string" => {
            let s = match v.as_str() {
                Some(s) => s,
                None => return Some("wrong type (expected string)".to_string()),
            };
            // R5-ZK-01/02: malformed bounds DENY; lengths count UTF-16 code units like `String.prototype.length`.
            let max = match obj.get("maxLength") {
                None => DEFAULT_MAX_STRING_LEN,
                Some(m) => match non_neg_int(m, ABSOLUTE_MAX_STRING_LEN as f64) {
                    Some(m) => m as usize,
                    None => return Some("malformed schema: maxLength".to_string()),
                },
            };
            let n = utf16_len(s);
            if n > max {
                return Some("exceeds maxLength".to_string());
            }
            if let Some(mi) = obj.get("minLength") {
                match non_neg_int(mi, ABSOLUTE_MAX_STRING_LEN as f64) {
                    Some(mi) if (n as f64) < mi => return Some("below minLength".to_string()),
                    Some(_) => {}
                    None => return Some("malformed schema: minLength".to_string()),
                }
            }
            if let Some(p) = obj.get("prefix") {
                match p.as_str() {
                    Some(p) => {
                        if !s.starts_with(p) {
                            return Some("violates prefix".to_string());
                        }
                    }
                    None => return Some("malformed schema: prefix".to_string()),
                }
            }
        }
        "number" | "integer" => {
            let f = match fin_num(v) {
                Some(f) => f,
                None => return Some("wrong type (expected number)".to_string()),
            };
            if t == "integer" && f.fract() != 0.0 {
                return Some("wrong type (expected integer)".to_string());
            }
            if let Some(mn) = obj.get("min") {
                match fin_num(mn) {
                    Some(mn) if f < mn => return Some("below min".to_string()),
                    Some(_) => {}
                    None => return Some("malformed schema: min".to_string()),
                }
            }
            if let Some(mx) = obj.get("max") {
                match fin_num(mx) {
                    Some(mx) if f > mx => return Some("above max".to_string()),
                    Some(_) => {}
                    None => return Some("malformed schema: max".to_string()),
                }
            }
        }
        "boolean" => {
            if !v.is_boolean() {
                return Some("wrong type (expected boolean)".to_string());
            }
        }
        _ => return Some("unknown type".to_string()),
    }
    if let Some(c) = obj.get("const") {
        if !scalar_eq(c, v) {
            return Some("violates const".to_string());
        }
    }
    if let Some(e) = obj.get("enum").and_then(|e| e.as_array()) {
        if !e.iter().any(|x| scalar_eq(x, v)) {
            return Some("violates enum".to_string());
        }
    }
    None
}
