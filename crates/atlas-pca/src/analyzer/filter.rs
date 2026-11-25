//! Data filters: a residual compiled to a parameterized SQL filter and to a UCAST tree, and their evaluation over a row.

use super::js::*;
use serde_json::{json, Value};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

/// An expression the filter cannot express exactly (the caller falls back to per-row authorization).
struct Unsupported(String);

fn unsup(msg: impl Into<String>) -> ! {
    resume_unwind(Box::new(Unsupported(msg.into())))
}

/// `^[A-Za-z_][A-Za-z0-9_]{0,62}(\.[A-Za-z_][A-Za-z0-9_]{0,62})?$`
fn col_ok(t: &str) -> bool {
    let part = |p: &str| -> bool {
        let b = p.as_bytes();
        !b.is_empty() && b.len() <= 63 && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
    };
    match t.split_once('.') {
        None => part(t),
        Some((a, b)) => part(a) && part(b),
    }
}

fn scalar(v: &Value) -> bool {
    matches!(v, Value::Bool(_) | Value::String(_)) || is_fin(v)
}

fn col_of(path: &Value, cols: &Value) -> String {
    let cm = match obj(cols) {
        Some(m) => m,
        None => fail("columns is not an object"),
    };
    let c: &Value = match path.as_str() {
        Some(p) => cm.get(p).unwrap_or(undef()),
        None => undef(),
    };
    match c.as_str() {
        Some(t) if col_ok(t) => t.to_string(),
        _ => unsup(format!("field '{}' has no usable column", js(path))),
    }
}

fn t_only(t: &str) -> Value {
    json!({ "t": t })
}

fn f_and(mut xs: Vec<Value>) -> Value {
    match xs.len() {
        0 => t_only("true"),
        1 => xs.remove(0),
        _ => json!({"t": "and", "xs": xs}),
    }
}

fn f_or(mut xs: Vec<Value>) -> Value {
    match xs.len() {
        0 => t_only("false"),
        1 => xs.remove(0),
        _ => json!({"t": "or", "xs": xs}),
    }
}

fn f_coalesce(x: Value, def: bool) -> Value {
    json!({"t": "coalesce", "x": x, "def": def})
}

fn f_not(x: Value) -> Value {
    json!({"t": "not", "x": x})
}

fn f_cond(c: &Value, cols: &Value) -> Value {
    let m = match obj(c) {
        Some(m) => m,
        None => unsup("malformed condition"),
    };
    if is_group_map(m) {
        if let Some(xs) = m.get("all_of").and_then(Value::as_array) {
            if !xs.is_empty() {
                return f_and(xs.iter().map(|x| f_cond(x, cols)).collect());
            }
        }
        if let Some(xs) = m.get("any_of").and_then(Value::as_array) {
            if !xs.is_empty() {
                return f_or(xs.iter().map(|x| f_cond(x, cols)).collect());
            }
        }
        if let Some(n) = m.get("not") {
            return f_not(f_cond(n, cols));
        }
        unsup("empty condition group");
    }
    let lf = match leaf(c) {
        Some(l) => l,
        None => unsup("malformed condition"),
    };
    if lf.contains_key("ref") {
        unsup("cross-field ref");
    }
    let col = col_of(mg(lf, "field"), cols);
    let (v, op) = (mg(lf, "value"), mg(lf, "op"));
    let ops = op.as_str().unwrap_or("\u{0}");
    match ops {
        "eq" | "ne" => {
            if !scalar(v) {
                unsup(format!("{ops} against a non-scalar"));
            }
            json!({"t": "cmp", "col": col, "op": ops, "v": v})
        }
        "lt" | "lte" | "gt" | "gte" => {
            if !is_fin(v) {
                unsup("string ordering follows UTF-8 byte order, which SQL collations do not guarantee");
            }
            json!({"t": "cmp", "col": col, "op": ops, "v": v})
        }
        "in" | "nin" => {
            let l = match v.as_array() {
                Some(l) if !l.is_empty() => l,
                _ => unsup(format!("{ops} needs a non-empty list of scalars")),
            };
            if !l.iter().all(scalar) {
                unsup(format!("{ops} needs a non-empty list of scalars"));
            }
            json!({"t": "in", "col": col, "vs": l, "neg": ops == "nin"})
        }
        "prefix" => match v.as_str() {
            Some(t) => json!({"t": "prefix", "col": col, "prefix": t}),
            None => unsup("prefix needs a string"),
        },
        "exists" => json!({"t": "null", "col": col, "isNull": v.as_bool() == Some(false)}),
        _ => unsup(format!("operator '{}' has no exact SQL form", js(op))),
    }
}

fn resource_expr(p: &Value, cols: &Value) -> Value {
    let r = get(p, "resource");
    if is_undef(r) || strict_eq(r, &s("*")) {
        return t_only("true");
    }
    let col = col_of(&s("action.resource"), cols);
    let t = match r.as_str() {
        Some(t) => t,
        None => fail("resource.startsWith is not a function"),
    };
    if t.starts_with("re:") {
        unsup("regex resource matcher");
    }
    if let Some(pre) = t.strip_suffix('*') {
        return json!({"t": "prefix", "col": col, "prefix": pre});
    }
    json!({"t": "cmp", "col": col, "op": "eq", "v": t})
}

fn veto_expr(v: &Value, cols: &Value) -> Value {
    let wh = get(v, "when");
    let mut xs: Vec<Value> = vec![];
    if !is_undef(get(wh, "resource")) {
        xs.push(f_coalesce(resource_expr(wh, cols), true));
    }
    let empty = empty_arr();
    for c in req_list(nn(get(wh, "where"), &empty)) {
        xs.push(f_coalesce(f_cond(c, cols), true));
    }
    let mut parts = vec![f_and(xs)];
    let over = get(v, "over");
    if truthy(over) {
        let col = col_of(get(over, "path"), cols);
        parts.push(f_or(vec![
            json!({"t": "null", "col": col, "isNull": true}),
            json!({"t": "cmp", "col": col, "op": "lt", "v": 0}),
            u(vec![("t", s("cmp")), ("col", s(&col)), ("op", s("gt")), ("v", get(over, "threshold").clone())]),
        ]));
    }
    let unless = get(v, "unless");
    if get(v, "kind").as_str() != Some("approval") && truthy(unless) && super::dag::js_len(unless) > 0 {
        let us: Vec<Value> = req_list(unless).iter().map(|c| f_coalesce(f_cond(c, cols), false)).collect();
        parts.push(f_not(f_and(us)));
    }
    f_and(parts)
}

fn part_expr(p: &Value, cols: &Value, include: &Value) -> Value {
    let autonomous = include.as_str() == Some("autonomous");
    let mut permits: Vec<Value> = vec![];
    let empty = empty_arr();
    for x in req_list(get(p, "predicates")) {
        let mut xs = vec![resource_expr(x, cols)];
        for c in req_list(nn(get(x, "where"), &empty)) {
            xs.push(f_cond(c, cols));
        }
        permits.push(f_and(xs));
    }
    let mut gates = vec![f_or(permits)];
    for v in req_list(get(p, "vetoes")) {
        let e = veto_expr(v, cols);
        // an approval veto sends the row to a human: it leaves the autonomous set but stays in the admitted set
        if get(v, "kind").as_str() == Some("deny") || autonomous {
            gates.push(f_not(e));
        }
    }
    for t in req_list(get(p, "tighten")) {
        if autonomous || get(t, "signal").as_str() == Some("deny") {
            gates.push(f_not(f_coalesce(f_cond(get(t, "when"), cols), true)));
        }
    }
    f_and(gates)
}

fn sql_op(op: &str) -> &'static str {
    match op {
        "eq" => "=",
        "ne" => "<>",
        "lt" => "<",
        "lte" => "<=",
        "gt" => ">",
        "gte" => ">=",
        _ => "",
    }
}

fn like_escape(t: &str) -> String {
    let mut out = String::new();
    for c in t.chars() {
        match c {
            '!' => out.push_str("!!"),
            '%' => out.push_str("!%"),
            '_' => out.push_str("!_"),
            c => out.push(c),
        }
    }
    out
}

fn render(x: &Value, dialect: &Value, params: &mut Vec<Value>) -> String {
    let col = || own(x, "col").as_str().unwrap_or("").to_string();
    match own(x, "t").as_str().unwrap_or("") {
        "true" => "TRUE".to_string(),
        "false" => "FALSE".to_string(),
        "cmp" => {
            params.push(own(x, "v").clone());
            let ph = if dialect.as_str() == Some("postgres") { format!("${}", params.len()) } else { "?".to_string() };
            format!("{} {} {}", col(), sql_op(own(x, "op").as_str().unwrap_or("")), ph)
        }
        "in" => {
            let mut ps: Vec<String> = vec![];
            for v in req_list(own(x, "vs")) {
                params.push(v.clone());
                ps.push(if dialect.as_str() == Some("postgres") { format!("${}", params.len()) } else { "?".to_string() });
            }
            let neg = if own(x, "neg").as_bool() == Some(true) { "NOT IN" } else { "IN" };
            format!("{} {} ({})", col(), neg, ps.join(", "))
        }
        "prefix" => {
            params.push(s(&format!("{}%", like_escape(req_str(own(x, "prefix"), "prefix")))));
            let ph = if dialect.as_str() == Some("postgres") { format!("${}", params.len()) } else { "?".to_string() };
            format!("{} LIKE {} ESCAPE '!'", col(), ph)
        }
        "null" => {
            if own(x, "isNull").as_bool() == Some(true) {
                format!("{} IS NULL", col())
            } else {
                format!("{} IS NOT NULL", col())
            }
        }
        t @ ("and" | "or") => {
            let sep = if t == "and" { " AND " } else { " OR " };
            let parts: Vec<String> = req_list(own(x, "xs")).iter().map(|y| render(y, dialect, params)).collect();
            format!("({})", parts.join(sep))
        }
        "not" => format!("NOT ({})", render(own(x, "x"), dialect, params)),
        _ => {
            let d = if own(x, "def").as_bool() == Some(true) { "TRUE" } else { "FALSE" };
            format!("COALESCE({}, {})", render(own(x, "x"), dialect, params), d)
        }
    }
}

/// Compiles a residual to a parameterized SQL filter (`{ok, expr, sql, params, ucast}`), or `{ok: false, reason}` when it cannot be
/// done exactly (the caller then falls back to per-row authorization).
pub(crate) fn to_filter(res: &Value, o: &Value) -> Value {
    let r = catch_unwind(AssertUnwindSafe(|| to_filter_inner(res, o)));
    match r {
        Ok(v) => v,
        Err(e) => match e.downcast_ref::<Unsupported>() {
            Some(un) => u(vec![("ok", Value::Bool(false)), ("reason", s(&un.0))]),
            None => u(vec![("ok", Value::Bool(false)), ("reason", s("filter compilation error"))]),
        },
    }
}

fn to_filter_inner(res: &Value, o: &Value) -> Value {
    if get(res, "decision").as_str() == Some("never") {
        let f = t_only("false");
        let uc = to_ucast(&f);
        return u(vec![("ok", Value::Bool(true)), ("expr", f), ("sql", s("FALSE")), ("params", empty_arr()), ("ucast", uc)]);
    }
    let dflt = s("autonomous");
    let include = nn(get(o, "include"), &dflt);
    let pol = get(res, "policy");
    if !is_obj(pol) {
        fail("policy is not an object");
    }
    let mut own_p = copy_map(pol);
    own_p.remove("meet");
    let cols = get(o, "columns");
    let mut xs = vec![part_expr(&Value::Object(own_p), cols, include)];
    let empty = empty_arr();
    for p in req_list(nn(own(pol, "meet"), &empty)) {
        xs.push(part_expr(p, cols, include));
    }
    let expr = f_and(xs);
    let mut params: Vec<Value> = vec![];
    let pg = s("postgres");
    let sql = render(&expr, nn(get(o, "dialect"), &pg), &mut params);
    let uc = to_ucast(&expr);
    u(vec![("ok", Value::Bool(true)), ("expr", expr), ("sql", s(&sql)), ("params", Value::Array(params)), ("ucast", uc)])
}

pub(crate) fn typeof_v(x: &Value) -> &'static str {
    if is_undef(x) {
        return "undefined";
    }
    match x {
        Value::Bool(_) => "boolean",
        Value::String(_) => "string",
        _ => {
            if is_num(x) {
                "number"
            } else {
                "object"
            }
        }
    }
}

fn row_get(row: &Value, c: &str) -> Value {
    match obj(row).and_then(|m| m.get(c)) {
        Some(v) => v.clone(),
        None => Value::Null,
    }
}

/// `a OP b` of two values of the same type.
fn ord2(op: &str, a: &Value, b: &Value) -> bool {
    let (less, greater) = if typeof_v(a) == "number" {
        let (x, y) = (to_number(a), to_number(b));
        (x < y, x > y)
    } else {
        (lt(a, b), gt(a, b))
    };
    match op {
        "lt" => less,
        "lte" => !greater,
        "gt" => greater,
        _ => !less,
    }
}

fn k_eval(x: &Value, row: &Value) -> Value {
    let t = own(x, "t").as_str().unwrap_or("");
    match t {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "cmp" => {
            let a = row_get(row, req_str(own(x, "col"), "col"));
            let b = own(x, "v");
            if a.is_null() || typeof_v(&a) != typeof_v(b) {
                return Value::Null;
            }
            let op = req_str(own(x, "op"), "op");
            if op == "eq" {
                return Value::Bool(strict_eq(&a, b));
            }
            if op == "ne" {
                return Value::Bool(!strict_eq(&a, b));
            }
            if typeof_v(&a) == "object" {
                return Value::Bool(false);
            }
            Value::Bool(ord2(op, &a, b))
        }
        "in" => {
            let a = row_get(row, req_str(own(x, "col"), "col"));
            if a.is_null() {
                return Value::Null;
            }
            let mut hit = false;
            for v in req_list(own(x, "vs")) {
                if strict_eq(v, &a) {
                    hit = true;
                }
            }
            if own(x, "neg").as_bool() == Some(true) {
                return Value::Bool(!hit);
            }
            Value::Bool(hit)
        }
        "prefix" => {
            let a = row_get(row, req_str(own(x, "col"), "col"));
            match a.as_str() {
                Some(t) => Value::Bool(t.starts_with(req_str(own(x, "prefix"), "prefix"))),
                None => Value::Null,
            }
        }
        "null" => {
            let a = row_get(row, req_str(own(x, "col"), "col"));
            Value::Bool(a.is_null() == (own(x, "isNull").as_bool() == Some(true)))
        }
        "and" | "or" => {
            let stop = t == "or";
            let mut unk = false;
            for y in req_list(own(x, "xs")) {
                let v = k_eval(y, row);
                if let Some(b) = v.as_bool() {
                    if b == stop {
                        return Value::Bool(stop);
                    }
                }
                if v.is_null() {
                    unk = true;
                }
            }
            if unk {
                return Value::Null;
            }
            Value::Bool(!stop)
        }
        "not" => {
            let v = k_eval(own(x, "x"), row);
            match v.as_bool() {
                Some(b) => Value::Bool(!b),
                None => Value::Null,
            }
        }
        _ => {
            let v = k_eval(own(x, "x"), row);
            if v.is_null() {
                return Value::Bool(own(x, "def").as_bool() == Some(true));
            }
            v
        }
    }
}

/// Evaluates a filter expression over one row with SQL's three-valued logic: true, false or null (NULL).
pub(crate) fn eval_filter(e: &Value, row: &Value) -> Value {
    if !is_obj(e) {
        fail("expression is not an object");
    }
    k_eval(e, row)
}

// ---- UCAST ------------------------------------------------------------------------------------------------------------------

fn compound(op: &str, value: Vec<Value>) -> Value {
    json!({"type": "compound", "operator": op, "value": value})
}

fn u_empty(x: &Value, op: &str) -> bool {
    own(x, "type").as_str() == Some("compound") && own(x, "operator").as_str() == Some(op) && req_list(own(x, "value")).is_empty()
}

fn u_join(op: &str, xs: Vec<Value>) -> Value {
    let other = if op == "and" { "or" } else { "and" };
    let mut flat: Vec<Value> = vec![];
    for x in xs {
        if own(&x, "type").as_str() == Some("compound") && own(&x, "operator").as_str() == Some(op) {
            flat.extend(req_list(own(&x, "value")).iter().cloned());
        } else {
            flat.push(x);
        }
    }
    if flat.iter().any(|x| u_empty(x, other)) {
        return compound(other, vec![]);
    }
    let mut kept: Vec<Value> = flat.into_iter().filter(|x| !u_empty(x, op)).collect();
    if kept.len() == 1 {
        return kept.remove(0);
    }
    compound(op, kept)
}

fn u_not(x: Value) -> Value {
    compound("not", vec![x])
}

fn u_f(field: &str, operator: &str, value: Value) -> Value {
    json!({"type": "field", "field": field, "operator": operator, "value": value})
}

fn u_not_null(c: &str) -> Value {
    u_f(c, "ne", Value::Null)
}

fn inv_op(op: &str) -> &'static str {
    match op {
        "eq" => "ne",
        "ne" => "eq",
        "lt" => "gte",
        "lte" => "gt",
        "gt" => "lte",
        "gte" => "lt",
        _ => "",
    }
}

fn u_list(xs: &Value, f: fn(&Value) -> Value) -> Vec<Value> {
    req_list(xs)
        .iter()
        .map(|y| {
            if !is_obj(y) {
                fail("not an object");
            }
            f(y)
        })
        .collect()
}

fn u_t(x: &Value) -> Value {
    let col = own(x, "col").as_str().unwrap_or("");
    match own(x, "t").as_str().unwrap_or("") {
        "true" => u_join("and", vec![]),
        "false" => u_join("or", vec![]),
        "cmp" => {
            if own(x, "op").as_str() == Some("ne") {
                return u_join("and", vec![u_not_null(col), u_f(col, "ne", own(x, "v").clone())]);
            }
            u_f(col, req_str(own(x, "op"), "op"), own(x, "v").clone())
        }
        "in" => {
            if own(x, "neg").as_bool() == Some(true) {
                return u_join("and", vec![u_not_null(col), u_f(col, "nin", own(x, "vs").clone())]);
            }
            u_f(col, "in", own(x, "vs").clone())
        }
        "prefix" => u_f(col, "startswith", own(x, "prefix").clone()),
        "null" => {
            if own(x, "isNull").as_bool() == Some(true) {
                u_f(col, "eq", Value::Null)
            } else {
                u_not_null(col)
            }
        }
        "and" => u_join("and", u_list(own(x, "xs"), u_t)),
        "or" => u_join("or", u_list(own(x, "xs"), u_t)),
        "not" => u_fl(own(x, "x")),
        _ => {
            if own(x, "def").as_bool() == Some(true) {
                u_not(u_fl(own(x, "x")))
            } else {
                u_t(own(x, "x"))
            }
        }
    }
}

fn u_fl(x: &Value) -> Value {
    let col = own(x, "col").as_str().unwrap_or("");
    match own(x, "t").as_str().unwrap_or("") {
        "true" => u_join("or", vec![]),
        "false" => u_join("and", vec![]),
        "cmp" => u_join("and", vec![u_not_null(col), u_f(col, inv_op(req_str(own(x, "op"), "op")), own(x, "v").clone())]),
        "in" => {
            if own(x, "neg").as_bool() == Some(true) {
                return u_f(col, "in", own(x, "vs").clone());
            }
            u_join("and", vec![u_not_null(col), u_f(col, "nin", own(x, "vs").clone())])
        }
        "prefix" => u_join("and", vec![u_not_null(col), u_not(u_f(col, "startswith", own(x, "prefix").clone()))]),
        "null" => {
            if own(x, "isNull").as_bool() == Some(true) {
                u_not_null(col)
            } else {
                u_f(col, "eq", Value::Null)
            }
        }
        "and" => u_join("or", u_list(own(x, "xs"), u_fl)),
        "or" => u_join("and", u_list(own(x, "xs"), u_fl)),
        "not" => u_t(own(x, "x")),
        _ => {
            if own(x, "def").as_bool() == Some(true) {
                u_fl(own(x, "x"))
            } else {
                u_not(u_t(own(x, "x")))
            }
        }
    }
}

/// The filter as a UCAST tree whose rows are exactly those the SQL form selects.
pub(crate) fn to_ucast(e: &Value) -> Value {
    if !is_obj(e) {
        fail("expression is not an object");
    }
    u_t(e)
}

/// Evaluates a UCAST tree over one row (two-valued; a comparison with NULL is false).
pub(crate) fn eval_ucast(uv: &Value, row: &Value) -> bool {
    if !is_obj(uv) {
        fail("node is not an object");
    }
    if own(uv, "type").as_str() == Some("compound") {
        let kids = req_list(own(uv, "value"));
        match own(uv, "operator").as_str().unwrap_or("") {
            "and" => return kids.iter().all(|c| eval_ucast(c, row)),
            "or" => return kids.iter().any(|c| eval_ucast(c, row)),
            _ => {}
        }
        if kids.is_empty() {
            fail("cannot read properties of undefined");
        }
        return !eval_ucast(&kids[0], row);
    }
    let field = own(uv, "field").as_str().unwrap_or("");
    let a = row_get(row, field);
    let v = nil_if_undef(own(uv, "value"));
    let op = own(uv, "operator").as_str().unwrap_or("");
    if op == "eq" && v.is_null() {
        return a.is_null();
    }
    if op == "ne" && v.is_null() {
        return !a.is_null();
    }
    if a.is_null() {
        return false;
    }
    match op {
        "eq" => strict_eq(&a, &v),
        "ne" | "lt" | "lte" | "gt" | "gte" => {
            if typeof_v(&a) != typeof_v(&v) {
                return false;
            }
            if op == "ne" {
                return !strict_eq(&a, &v);
            }
            if typeof_v(&a) == "object" {
                return false;
            }
            ord2(op, &a, &v)
        }
        "in" => req_list(&v).iter().any(|e| strict_eq(e, &a)),
        "nin" => !req_list(&v).iter().any(|e| strict_eq(e, &a)),
        "startswith" => match a.as_str() {
            Some(t) => t.starts_with(req_str(&v, "prefix")),
            None => false,
        },
        _ => false,
    }
}
