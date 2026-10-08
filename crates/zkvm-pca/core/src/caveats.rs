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
    pub reversibility_class: Option<String>,
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
            let lim = class_rank(obj.get("class").and_then(|c| c.as_str()));
            let cur = class_rank(ctx.reversibility_class.as_deref());
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
        "tool_schema" => evaluate_tool_schema(obj, ctx).is_none(),
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

/// Returns Some(error) when the tool call does NOT satisfy the caveat, or None when it does.
fn evaluate_tool_schema(cv: &serde_json::Map<String, Value>, ctx: &CaveatCtx) -> Option<String> {
    let tool = cv.get("tool").and_then(|t| t.as_str()).filter(|s| !s.is_empty());
    let tool = tool?; // malformed caveat (no tool) => unsatisfied
    let schema = cv.get("schema")?;

    // schema must validate
    if let Some(e) = validate_arg_schema(schema) {
        return Some(e);
    }
    // self-consistency: schema_digest + binding_digest
    let schema_digest = cv.get("schema_digest").and_then(|d| d.as_str())?;
    if hash_canonical(schema) != schema_digest {
        return Some("schema digest mismatch".to_string());
    }
    let sig_digest = cv
        .get("signature_digest")
        .map(value_to_string)
        .unwrap_or_default();
    let binding = json!({ "tool": tool, "signature_digest": sig_digest, "schema": schema });
    let binding_digest = cv.get("binding_digest").and_then(|d| d.as_str())?;
    if hash_canonical(&binding) != binding_digest {
        return Some("binding digest mismatch".to_string());
    }

    // the call
    let call_tool = ctx.tool.as_deref()?;
    let args = match &ctx.tool_args {
        Some(Value::Object(_)) => ctx.tool_args.as_ref().unwrap(),
        _ => return Some("malformed call".to_string()),
    };
    if call_tool != tool {
        return Some("tool not authorized".to_string());
    }
    if let Some(d) = &ctx.tool_signature_digest {
        if d != &sig_digest {
            return Some("signed tool_binding differs from the authorized tool signature".to_string());
        }
    }

    let props = schema.get("props")?;
    let required = schema.get("required");
    check_object(props, required, args, 1, &mut 0usize)
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn validate_arg_schema(schema: &Value) -> Option<String> {
    let obj = schema.as_object()?;
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
        if let Some(mi) = obj.get("minItems") {
            if !non_neg_int(mi, ABSOLUTE_MAX_ARRAY_ITEMS) {
                return Some("bad minItems".to_string());
            }
        }
        if let Some(ma) = obj.get("maxItems") {
            if !non_neg_int(ma, ABSOLUTE_MAX_ARRAY_ITEMS) {
                return Some("bad maxItems".to_string());
            }
        }
        if let (Some(mi), Some(ma)) = (obj.get("minItems").and_then(|v| v.as_u64()), obj.get("maxItems").and_then(|v| v.as_u64())) {
            if mi > ma {
                return Some("minItems > maxItems".to_string());
            }
        }
        return match obj.get("items") {
            Some(items) => spec_error(items, depth + 1, nodes),
            None => Some("unknown type".to_string()),
        };
    }
    // scalars: enum/const type checks
    let ok = |v: &Value| -> bool {
        match t {
            "string" => v.as_str().map(|s| s.len() <= 1024).unwrap_or(false),
            "boolean" => v.is_boolean(),
            "number" => v.as_f64().map(|f| f.is_finite()).unwrap_or(false),
            "integer" => v.as_i64().is_some() || v.as_u64().is_some(),
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
    None
}

fn non_neg_int(v: &Value, max: usize) -> bool {
    matches!(v.as_u64(), Some(n) if (n as usize) <= max)
}

fn check_object(
    props: &Value,
    required: Option<&Value>,
    obj: &Value,
    depth: usize,
    budget: &mut usize,
) -> Option<String> {
    let props = props.as_object()?;
    let map = obj.as_object()?;
    for k in map.keys() {
        if !props.contains_key(k) {
            return Some(format!("unexpected argument {}", k));
        }
    }
    if let Some(req) = required.and_then(|r| r.as_array()) {
        for r in req {
            if let Some(name) = r.as_str() {
                if !map.contains_key(name) {
                    return Some(format!("missing required argument '{}'", name));
                }
            }
        }
    }
    for (k, v) in map.iter() {
        if let Some(e) = check_value(props.get(k).unwrap(), v, depth + 1, budget) {
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
    let obj = spec.as_object()?;
    let t = obj.get("type").and_then(|x| x.as_str())?;
    match t {
        "object" => {
            if !v.is_object() {
                return Some("expected object".to_string());
            }
            if let Some(e) = check_object(obj.get("props")?, obj.get("required"), v, depth, budget) {
                return Some(e);
            }
            return None;
        }
        "array" => {
            let arr = match v.as_array() {
                Some(a) => a,
                None => return Some("expected array".to_string()),
            };
            let max = obj
                .get("maxItems")
                .and_then(|m| m.as_u64())
                .map(|m| (m as usize).min(ABSOLUTE_MAX_ARRAY_ITEMS))
                .unwrap_or(DEFAULT_MAX_ARRAY_ITEMS);
            if arr.len() > max {
                return Some("exceeds maxItems".to_string());
            }
            if let Some(mi) = obj.get("minItems").and_then(|m| m.as_u64()) {
                if arr.len() < mi as usize {
                    return Some("below minItems".to_string());
                }
            }
            let items = obj.get("items")?;
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
            let max = obj
                .get("maxLength")
                .and_then(|m| m.as_u64())
                .map(|m| (m as usize).min(ABSOLUTE_MAX_STRING_LEN))
                .unwrap_or(DEFAULT_MAX_STRING_LEN);
            if s.chars().count() > max {
                return Some("exceeds maxLength".to_string());
            }
            if let Some(mi) = obj.get("minLength").and_then(|m| m.as_u64()) {
                if (s.chars().count() as u64) < mi {
                    return Some("below minLength".to_string());
                }
            }
            if let Some(p) = obj.get("prefix").and_then(|p| p.as_str()) {
                if !s.starts_with(p) {
                    return Some("violates prefix".to_string());
                }
            }
        }
        "number" | "integer" => {
            let f = match v.as_f64() {
                Some(f) if f.is_finite() => f,
                _ => return Some("wrong type (expected number)".to_string()),
            };
            if t == "integer" && v.as_i64().is_none() && v.as_u64().is_none() {
                return Some("wrong type (expected integer)".to_string());
            }
            if let Some(mn) = obj.get("min").and_then(|m| m.as_f64()) {
                if f < mn {
                    return Some("below min".to_string());
                }
            }
            if let Some(mx) = obj.get("max").and_then(|m| m.as_f64()) {
                if f > mx {
                    return Some("above max".to_string());
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
        if c != v {
            return Some("violates const".to_string());
        }
    }
    if let Some(e) = obj.get("enum").and_then(|e| e.as_array()) {
        if !e.iter().any(|x| x == v) {
            return Some("violates enum".to_string());
        }
    }
    None
}
