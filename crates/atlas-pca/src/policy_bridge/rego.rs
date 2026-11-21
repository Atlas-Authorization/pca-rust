//! OPA / Rego `allow` rules (a conjunction of input comparisons per rule) as permit predicates.
use super::*;

static COMMENT: LazyLock<Regex> = LazyLock::new(|| rx("#[^\n]*"));
static PKG: LazyLock<Regex> = LazyLock::new(|| rx("§Bpackage§S+([A-Za-z_][A-Za-z0-9_.]*)"));
static DEFAULT: LazyLock<Regex> = LazyLock::new(|| rx("§Bdefault§S+allow§S*(?::?=)§S*(true|false)§B"));
static ALLOW: LazyLock<Regex> = LazyLock::new(|| rx("§Ballow§B§S*(?:(?::?=§S*true§B|=§S*true§B|§Bif§B)§S*)?\\{"));
static NOT: LazyLock<Regex> = LazyLock::new(|| rx_full("not§S+([\\s\\S]+)"));
static UNMODELED_A: LazyLock<Regex> = LazyLock::new(|| rx(":=|§Bsome§B|§Bevery§B|\\[§D*\\|§D*\\]"));
static UNMODELED_IDX: LazyLock<Regex> = LazyLock::new(|| rx("§Binput\\.[A-Za-z0-9_.]*\\["));
static REGO_CMP: LazyLock<Regex> = LazyLock::new(|| rx_full("(input\\.[A-Za-z0-9_.]+)§S*(==|!=|<=|>=|<|>|§Bin§B)§S*([\\s\\S]+)"));
static INPUT_PATH: LazyLock<Regex> = LazyLock::new(|| rx_full("input\\.[A-Za-z0-9_.]+"));
static STARTSWITH: LazyLock<Regex> = LazyLock::new(|| rx_full("startswith\\(§S*(input\\.[A-Za-z0-9_.]+)§S*,§S*\"([^\"]*)\"§S*\\)"));
static GLOB: LazyLock<Regex> = LazyLock::new(|| rx_full("glob\\.match\\(§S*\"([^\"]*)\"§S*,§S*(\\[§S*\\]|null)§S*,§S*(input\\.[A-Za-z0-9_.]+)§S*\\)"));
static REGO_STR: LazyLock<Regex> = LazyLock::new(|| rx_full("\"([^\"]*)\""));
static NUM_LIT: LazyLock<Regex> = LazyLock::new(|| rx_full("-?[0-9]+(?:\\.[0-9]+)?"));
static GLOB_BAD: LazyLock<Regex> = LazyLock::new(|| rx("[\\[\\]{}]"));
static GLOB_META: LazyLock<Regex> = LazyLock::new(|| rx("[*?\\\\]"));

/// OPA / Rego `allow` rules (a conjunction of input comparisons per rule) as permit predicates; anything else drops its rule.
pub fn rego_to_pca(module_text: &str) -> Value {
    let mut report = Report::new("rego");
    let mut predicates = Vec::new();
    let src = COMMENT.replace_all(module_text, "").into_owned();
    if let Some(p) = PKG.captures(&src) {
        report.translated.push(format!("package {}", &p[1]));
    }
    match DEFAULT.captures(&src) {
        Some(d) if &d[1] == "true" => {
            report.skipped.push("`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny".into())
        }
        Some(_) => {}
        None => report.skipped.push("no `default allow = false` found; assuming default-deny".into()),
    }
    for body in extract_allow_bodies(&src, &mut report) {
        translate_rule(&body, &mut predicates, &mut report);
    }
    result(predicates, vec![], report)
}

fn extract_allow_bodies(src: &str, report: &mut Report) -> Vec<String> {
    let mut bodies = Vec::new();
    let mut pos = 0;
    while let Some(m) = ALLOW.find_at(src, pos) {
        let open = m.end() - 1;
        match match_delim(src, open, b'{', b'}') {
            Some(close) => {
                bodies.push(src[open + 1..close].to_string());
                pos = close + 1;
            }
            None => {
                report.errors.push("unterminated `allow { ... }` block".into());
                break;
            }
        }
    }
    bodies
}

enum Stmt {
    Unmodeled,
    Verb(Value),
    Resource(String),
    Cond(Value),
}

fn as_list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        o => vec![o.clone()],
    }
}

fn translate_rule(body: &str, predicates: &mut Vec<Value>, report: &mut Report) {
    let statements: Vec<&str> = body.split(['\n', ';']).map(trim).filter(|t| !t.is_empty()).collect();
    let mut verb = json!("*");
    let mut resource: Option<String> = None;
    let mut where_: Vec<Value> = Vec::new();
    for stmt in statements {
        match parse_statement(stmt, 0) {
            Stmt::Unmodeled => {
                report.skipped.push(format!("unmodeled statement \"{}\" \u{2014} rule dropped (fail closed)", truncate(stmt)));
                return;
            }
            Stmt::Verb(v) => {
                if verb == json!("*") {
                    verb = v;
                } else {
                    let have = as_list(&verb);
                    let nxt = as_list(&v);
                    let both: Vec<Value> = have.into_iter().filter(|x| nxt.contains(x)).collect();
                    if both.is_empty() {
                        report.translated.push("rule can never match (contradictory action selectors), nothing emitted".into());
                        return;
                    }
                    verb = if both.len() == 1 { both[0].clone() } else { Value::Array(both) };
                }
            }
            Stmt::Resource(r) => {
                if resource.as_ref().is_some_and(|x| *x != r) {
                    report.translated.push("rule can never match (contradictory resource selectors), nothing emitted".into());
                    return;
                }
                resource = Some(r);
            }
            Stmt::Cond(c) => where_.push(c),
        }
    }
    let mut predicate = Map::new();
    predicate.insert("verb".into(), verb.clone());
    if let Some(r) = &resource {
        predicate.insert("resource".into(), json!(r));
    }
    if !where_.is_empty() {
        predicate.insert("where".into(), Value::Array(where_.clone()));
    }
    let on = match &resource {
        Some(r) if !r.is_empty() => format!(" on {r}"),
        _ => String::new(),
    };
    predicates.push(Value::Object(predicate));
    report.translated.push(format!("allow \u{2192} verb {}{} ({} condition(s))", serde_json::to_string(&verb).unwrap_or_default(), on, where_.len()));
}

fn parse_statement(stmt: &str, depth: usize) -> Stmt {
    if depth > MAX_FRAMES {
        return Stmt::Unmodeled;
    }
    let s = trim(stmt);
    if let Some(nm) = NOT.captures(s) {
        let c = match parse_statement(trim(&nm[1]), depth + 1) {
            Stmt::Cond(c) => c,
            _ => return Stmt::Unmodeled,
        };
        if c.get("op").and_then(Value::as_str) == Some("eq") {
            if let Some(f) = c.get("field").and_then(Value::as_str) {
                let mut needs = vec![exists(f)];
                if let Some(r) = c.get("ref").and_then(Value::as_str) {
                    needs.push(exists(r));
                }
                needs.push(c.clone());
                return Stmt::Cond(json!({ "not": { "all_of": needs } }));
            }
        }
        return Stmt::Cond(json!({ "not": c }));
    }
    if let Some(b) = parse_builtin(s) {
        return b;
    }
    if UNMODELED_A.is_match(s) || s.contains('(') || UNMODELED_IDX.is_match(s) {
        return Stmt::Unmodeled;
    }
    let m = match REGO_CMP.captures(s) {
        Some(m) => m,
        None => return Stmt::Unmodeled,
    };
    let (path, op_tok, rhs_raw) = (&m[1], &m[2], trim(&m[3]));
    let sub = &path["input.".len()..];
    if op_tok == "in" {
        let values = match parse_set_literal(rhs_raw) {
            Some(v) => v,
            None => return Stmt::Unmodeled,
        };
        if sub == "action" {
            if !values.iter().all(Value::is_string) {
                return Stmt::Unmodeled;
            }
            return Stmt::Verb(Value::Array(values));
        }
        return Stmt::Cond(json!({ "field": format!("env.{sub}"), "op": "in", "value": values }));
    }
    if (op_tok == "==" || op_tok == "!=") && INPUT_PATH.is_match(rhs_raw) {
        let op = if op_tok == "!=" { "ne" } else { "eq" };
        let other = format!("env.{}", &rhs_raw["input.".len()..]);
        return Stmt::Cond(json!({ "field": format!("env.{sub}"), "op": op, "ref": other }));
    }
    let value = match rego_literal(rhs_raw) {
        Some(v) => v,
        None => return Stmt::Unmodeled,
    };
    if op_tok == "==" {
        if let Some(sv) = value.as_str() {
            if sub == "action" {
                return Stmt::Verb(json!(sv));
            }
            if sub == "resource" {
                return Stmt::Resource(sv.to_string());
            }
        }
        return Stmt::Cond(json!({ "field": format!("env.{sub}"), "op": "eq", "value": value }));
    }
    if op_tok == "!=" {
        return Stmt::Cond(json!({ "field": format!("env.{sub}"), "op": "ne", "value": value }));
    }
    if !value.is_number() {
        return Stmt::Unmodeled;
    }
    let cmp = match op_tok {
        "<" => "lt",
        "<=" => "lte",
        ">" => "gt",
        _ => "gte",
    };
    Stmt::Cond(json!({ "field": format!("env.{sub}"), "op": cmp, "value": value }))
}

fn parse_builtin(s: &str) -> Option<Stmt> {
    if let Some(sw) = STARTSWITH.captures(s) {
        return Some(Stmt::Cond(json!({ "field": format!("env.{}", &sw[1]["input.".len()..]), "op": "prefix", "value": &sw[2] })));
    }
    let gm = GLOB.captures(s)?;
    let pattern = &gm[1];
    if GLOB_BAD.is_match(pattern) {
        return Some(Stmt::Unmodeled);
    }
    if gm[2].starts_with('[') && GLOB_META.is_match(pattern) {
        return Some(Stmt::Unmodeled);
    }
    Some(Stmt::Cond(json!({ "field": format!("env.{}", &gm[3]["input.".len()..]), "op": "like", "value": pattern })))
}

fn rego_literal(expr: &str) -> Option<Value> {
    let s = trim(expr);
    if let Some(m) = REGO_STR.captures(s) {
        return Some(json!(&m[1]));
    }
    match s {
        "true" => return Some(json!(true)),
        "false" => return Some(json!(false)),
        _ => {}
    }
    NUM_LIT.is_match(s).then(|| number(s))
}

fn parse_set_literal(expr: &str) -> Option<Vec<Value>> {
    let s = trim(expr);
    let is_set = s.starts_with('{') && s.ends_with('}');
    let is_arr = s.starts_with('[') && s.ends_with(']');
    if !is_set && !is_arr {
        return None;
    }
    let mut values = Vec::new();
    for it in trimmed_non_empty(&split_top_level(drop_ends(s), ",")) {
        values.push(rego_literal(&it)?);
    }
    Some(values)
}
