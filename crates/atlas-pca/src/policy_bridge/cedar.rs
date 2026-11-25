//! Cedar `permit` / `forbid` policies as permit predicates and deny predicates (consume with [`super::decide`]).
use super::*;

type R<T> = Result<T, String>;

const ENTITY_PARENTS: &str = "env.entity_parents";

/// Cedar `permit` / `forbid` policies as permit predicates and deny predicates (consume with `decide`).
pub fn cedar_to_pca(policy_text: &str) -> Value {
    translate_cedar(policy_text, true)
}

/// `error_guards = false` omits the trailing "no attribute was missing" guard (bare structure; not exact).
pub fn translate_cedar(policy_text: &str, error_guards: bool) -> Value {
    let mut report = Report::new("cedar");
    let (mut predicates, mut denies) = (Vec::new(), Vec::new());
    let cleaned = COMMENT.replace_all(policy_text, "").into_owned();
    for stmt in trimmed_non_empty(&split_top_level(&cleaned, ";")) {
        if let Err(e) = translate_statement(&stmt, &mut predicates, &mut denies, &mut report, error_guards) {
            report.errors.push(format!("policy \"{}\": {}", truncate(&stmt), e));
        }
    }
    result(predicates, denies, report)
}

static COMMENT: LazyLock<Regex> = LazyLock::new(|| rx("//[^\n]*"));
static ANNOT: LazyLock<Regex> = LazyLock::new(|| rx("\\A§S*(?:@[A-Za-z_]§W*§S*\\([^)]*\\)§S*)+"));
static HEAD: LazyLock<Regex> = LazyLock::new(|| rx("\\A§S*((?i-u:permit|forbid))§S*\\("));
static SCOPE: LazyLock<Regex> = LazyLock::new(|| rx_full("(principal|action|resource)§B§S*(?:(==|in|is)§S*)?([\\s\\S]*)"));
static BLOCK: LazyLock<Regex> = LazyLock::new(|| rx("§B(when|unless)§B§S*\\{"));
static WORD_OP: LazyLock<Regex> = LazyLock::new(|| rx_full("([\\s\\S]*?§N)§S+(in|is|like|has)§S+([\\s\\S]+)"));
static IDENT: LazyLock<Regex> = LazyLock::new(|| rx_full("[A-Za-z_]§W*"));
static PATH_HEAD: LazyLock<Regex> = LazyLock::new(|| rx("\\A(principal|resource|action|context)§B"));
static P_PRINCIPAL: LazyLock<Regex> = LazyLock::new(|| rx_full("principal\\.([A-Za-z_][A-Za-z0-9_.]*)"));
static P_RESOURCE: LazyLock<Regex> = LazyLock::new(|| rx_full("resource\\.([A-Za-z_][A-Za-z0-9_.]*)"));
static P_CONTEXT: LazyLock<Regex> = LazyLock::new(|| rx_full("context\\.([A-Za-z_][A-Za-z0-9_.]*)"));
static TYPE_NAME: LazyLock<Regex> = LazyLock::new(|| rx_full("[A-Za-z_]§W*(?:::[A-Za-z_]§W*)*"));
static ENTITY_ID: LazyLock<Regex> = LazyLock::new(|| rx_full("§D+::\"([^\"]*)\""));
static ENTITY_UID: LazyLock<Regex> = LazyLock::new(|| rx_full("(§D+)::\"([^\"]*)\""));
static STR_LIT: LazyLock<Regex> = LazyLock::new(|| rx_full("\"([^\"]*)\""));
static NUM_LIT: LazyLock<Regex> = LazyLock::new(|| rx_full("-?[0-9]+(?:\\.[0-9]+)?"));
static LIKE_STR: LazyLock<Regex> = LazyLock::new(|| rx_full("\"([\\s\\S]*)\""));
static LAST_SEG: LazyLock<Regex> = LazyLock::new(|| rx("\\.[^.]+\\z"));

struct Scope {
    verb: Value,
    resource: Option<String>,
    conds: Vec<Value>,
}

fn translate_statement(stmt: &str, permits: &mut Vec<Value>, denies: &mut Vec<Value>, report: &mut Report, error_guards: bool) -> R<()> {
    let mut body = stmt;
    if let Some(m) = ANNOT.find(body) {
        body = &body[m.end()..];
    }
    let head = match HEAD.captures(body) {
        Some(h) => h,
        None => {
            report.skipped.push(format!("unrecognized statement: \"{}\"", truncate(stmt)));
            return Ok(());
        }
    };
    let forbid = head[1].eq_ignore_ascii_case("forbid");
    let open_idx = body.find('(').ok_or("unterminated scope parentheses")?;
    let close_idx = match_delim(body, open_idx, b'(', b')').ok_or("unterminated scope parentheses")?;
    let scope_text = &body[open_idx + 1..close_idx];
    let rest = &body[close_idx + 1..];
    let scope = parse_scope(scope_text)?;
    let mut where_: Vec<Value> = scope.conds.clone();
    let mut guards: Vec<Value> = Vec::new();
    for (kind, text) in parse_condition_blocks(rest)? {
        let parsed = match parse_expr(&text, 0)? {
            Some(p) => p,
            None => {
                report.skipped.push(format!("unmodeled {}-condition \"{}\" \u{2014} policy dropped (fail closed)", kind, truncate(&text)));
                if forbid {
                    report
                        .errors
                        .push(format!("forbid could not be fully modeled and was dropped \u{2014} treat result as fail-closed: \"{}\"", truncate(stmt)));
                }
                return Ok(());
            }
        };
        let g = no_error(&parsed, 0)?;
        where_.push(if kind == "when" { parsed } else { json!({ "not": parsed }) });
        if let Some(g) = g {
            guards.push(g);
        }
    }
    let condition_count = where_.len();
    if error_guards && !guards.is_empty() {
        where_.push(if guards.len() == 1 { guards.remove(0) } else { json!({ "all_of": guards }) });
    }
    let mut predicate = Map::new();
    predicate.insert("verb".into(), scope.verb.clone());
    if let Some(r) = &scope.resource {
        predicate.insert("resource".into(), json!(r));
    }
    if !where_.is_empty() {
        predicate.insert("where".into(), Value::Array(where_));
    }
    let on = match &scope.resource {
        Some(r) if !r.is_empty() => format!(" on {r}"),
        _ => String::new(),
    };
    let verb = serde_json::to_string(&scope.verb).unwrap_or_default();
    if forbid {
        denies.push(Value::Object(predicate));
        report.translated.push(format!("forbid \u{2192} deny verb {verb}{on} ({condition_count} condition(s))"));
    } else {
        permits.push(Value::Object(predicate));
        report.translated.push(format!("permit \u{2192} verb {verb}{on} ({condition_count} condition(s))"));
    }
    Ok(())
}

fn parse_scope(scope_text: &str) -> R<Scope> {
    let clauses = trimmed_non_empty(&split_top_level(scope_text, ","));
    let mut result = Scope { verb: json!("*"), resource: None, conds: vec![] };
    for clause in &clauses {
        let m = SCOPE.captures(clause).ok_or_else(|| format!("unparseable scope clause \"{}\"", truncate(clause)))?;
        let variable = m.get(1).map_or("", |x| x.as_str());
        let op = match m.get(2) {
            Some(o) => o.as_str(),
            None => continue,
        };
        let operand = trim(m.get(3).map_or("", |x| x.as_str()));
        if variable == "action" {
            if op == "==" {
                let eid = entity_id(operand).ok_or_else(|| format!("action == expects an Action entity, got \"{}\"", truncate(operand)))?;
                result.verb = json!(eid);
            } else if op == "in" && operand.starts_with('[') {
                let mut verbs = Vec::new();
                for it in trimmed_non_empty(&split_top_level(drop_ends(operand), ",")) {
                    let eid = entity_id(&it).ok_or_else(|| format!("action in [...] expects Action entities, got \"{}\"", truncate(&it)))?;
                    verbs.push(eid);
                }
                result.verb = json!(verbs);
            } else {
                return Err(format!("unsupported action scope operator \"{op}\""));
            }
        } else {
            let field = if variable == "resource" { "action.resource" } else { "subject.id" };
            if op == "==" {
                let uid = entity_uid(operand);
                if variable == "resource" {
                    result.resource = Some(uid.ok_or_else(|| format!("resource == expects an entity, got \"{}\"", truncate(operand)))?);
                } else {
                    let uid = uid.ok_or_else(|| format!("principal == expects an entity, got \"{}\"", truncate(operand)))?;
                    result.conds.push(json!({ "field": field, "op": "eq", "value": uid }));
                }
            } else if op == "is" {
                let t = type_name(operand).ok_or_else(|| format!("{variable} is expects a type, got \"{}\"", truncate(operand)))?;
                result.conds.push(json!({ "field": field, "op": "is_a", "value": t }));
            } else {
                let mem =
                    member_of_condition(field, operand).ok_or_else(|| format!("{variable} in expects an entity (hierarchy), got \"{}\"", truncate(operand)))?;
                result.conds.push(mem);
            }
        }
    }
    Ok(result)
}

fn parse_condition_blocks(rest: &str) -> R<Vec<(&'static str, String)>> {
    let mut blocks = Vec::new();
    let mut pos = 0;
    while let Some(m) = BLOCK.captures_at(rest, pos) {
        let whole = m.get(0).ok_or("block")?;
        let kind = if &m[1] == "unless" { "unless" } else { "when" };
        let open = whole.end() - 1;
        let close = match_delim(rest, open, b'{', b'}').ok_or_else(|| format!("unterminated {kind} block"))?;
        blocks.push((kind, rest[open + 1..close].to_string()));
        pos = close + 1;
    }
    Ok(blocks)
}

/// A boolean expression: `||` over `&&` over parenthesised groups over comparison atoms; `None` if any atom is outside the subset.
fn parse_expr(text: &str, depth: usize) -> R<Option<Value>> {
    if depth > MAX_FRAMES {
        return Err(STACK.into());
    }
    let t = trim(text);
    if t.is_empty() {
        return Ok(None);
    }
    let ors = trimmed_non_empty(&split_top_level(t, "||"));
    if ors.len() > 1 {
        let mut subs = Vec::new();
        for s in &ors {
            subs.push(parse_expr(s, depth + 1)?);
        }
        if subs.iter().any(Option::is_none) {
            return Ok(None);
        }
        return Ok(Some(json!({ "any_of": subs.into_iter().flatten().collect::<Vec<_>>() })));
    }
    let ands = trimmed_non_empty(&split_top_level(t, "&&"));
    if ands.len() > 1 {
        let mut subs = Vec::new();
        for s in &ands {
            subs.push(parse_expr(s, depth + 1)?);
        }
        if subs.iter().any(Option::is_none) {
            return Ok(None);
        }
        return Ok(Some(json!({ "all_of": subs.into_iter().flatten().collect::<Vec<_>>() })));
    }
    if t.starts_with('(') && match_delim(t, 0, b'(', b')') == Some(t.len() - 1) {
        return parse_expr(&t[1..t.len() - 1], depth + 1);
    }
    Ok(parse_atom(t))
}

const CMP_TOKENS: [(&str, &str); 6] = [("==", "eq"), ("!=", "ne"), ("<=", "lte"), (">=", "gte"), ("<", "lt"), (">", "gt")];

fn parse_atom(text: &str) -> Option<Value> {
    let t = trim(text);
    for (tok, op) in CMP_TOKENS {
        if let Some(idx) = index_of_top_level(t, tok) {
            return build_comparison(trim(&t[..idx]), op, trim(&t[idx + tok.len()..]));
        }
    }
    let wm = WORD_OP.captures(t)?;
    build_word_op(trim(&wm[1]), &wm[2], trim(&wm[3]))
}

fn build_comparison(lhs_raw: &str, op: &str, rhs_raw: &str) -> Option<Value> {
    let field = to_field_path(lhs_raw)?;
    if field == "action.verb" {
        if op != "eq" && op != "ne" {
            return None;
        }
        let eid = entity_id(rhs_raw)?;
        return Some(json!({ "field": field, "op": op, "value": eid }));
    }
    if is_path_expr(rhs_raw) {
        if let Some(r) = to_field_path(rhs_raw) {
            return Some(json!({ "field": field, "op": op, "ref": r }));
        }
    }
    let value = to_literal(rhs_raw)?;
    Some(json!({ "field": field, "op": op, "value": value }))
}

fn build_word_op(lhs_raw: &str, kind: &str, rhs_raw: &str) -> Option<Value> {
    if kind == "has" {
        if !IDENT.is_match(rhs_raw) {
            return None;
        }
        let field = to_field_path(&format!("{lhs_raw}.{rhs_raw}"))?;
        return Some(exists(&field));
    }
    let field = to_field_path(lhs_raw)?;
    if field == "action.verb" {
        if kind != "in" {
            return None;
        }
        let inner = if rhs_raw.starts_with('[') && rhs_raw.ends_with(']') { drop_ends(rhs_raw) } else { rhs_raw };
        let ids: Vec<Option<String>> = trimmed_non_empty(&split_top_level(inner, ",")).iter().map(|x| entity_id(x)).collect();
        if !ids.is_empty() && ids.iter().all(Option::is_some) {
            return Some(json!({ "field": field, "op": "in", "value": ids.into_iter().flatten().collect::<Vec<_>>() }));
        }
        return None;
    }
    if kind == "is" {
        let t = type_name(rhs_raw)?;
        return Some(json!({ "field": field, "op": "is_a", "value": t }));
    }
    if kind == "like" {
        let sm = LIKE_STR.captures(rhs_raw)?;
        return Some(json!({ "field": field, "op": "like", "value": cedar_like_to_glob(&sm[1]) }));
    }
    if rhs_raw.starts_with('[') {
        let inner = if rhs_raw.ends_with(']') { drop_ends(rhs_raw) } else { &rhs_raw[1..] };
        let items = trimmed_non_empty(&split_top_level(inner, ","));
        if !items.is_empty() && items.iter().all(|it| entity_uid(it).is_some()) {
            let uids: Vec<String> = items.iter().filter_map(|it| entity_uid(it)).collect();
            return Some(json!({ "field": field, "op": "member_of", "value": uids, "collection": ENTITY_PARENTS }));
        }
        let mut values = Vec::new();
        for it in &items {
            values.push(to_literal(it)?);
        }
        return Some(json!({ "field": field, "op": "in", "value": values }));
    }
    member_of_condition(&field, rhs_raw)
}

fn member_of_condition(field: &str, operand: &str) -> Option<Value> {
    if let Some(uid) = entity_uid(operand) {
        return Some(json!({ "field": field, "op": "member_of", "value": uid, "collection": ENTITY_PARENTS }));
    }
    if is_path_expr(operand) {
        if let Some(r) = to_field_path(operand) {
            return Some(json!({ "field": field, "op": "member_of", "ref": r, "collection": ENTITY_PARENTS }));
        }
    }
    None
}

fn is_path_expr(expr: &str) -> bool {
    PATH_HEAD.is_match(expr)
}

fn to_field_path(expr: &str) -> Option<String> {
    match expr {
        "principal" => return Some("subject.id".into()),
        "resource" => return Some("action.resource".into()),
        "action" => return Some("action.verb".into()),
        "context" => return Some("env".into()),
        _ => {}
    }
    if let Some(m) = P_PRINCIPAL.captures(expr) {
        return Some(format!("subject.{}", &m[1]));
    }
    if let Some(m) = P_RESOURCE.captures(expr) {
        return Some(format!("env.resource.{}", &m[1]));
    }
    if let Some(m) = P_CONTEXT.captures(expr) {
        return Some(format!("env.{}", &m[1]));
    }
    None
}

fn type_name(expr: &str) -> Option<String> {
    let s = trim(expr);
    TYPE_NAME.is_match(s).then(|| s.to_string())
}

fn entity_id(expr: &str) -> Option<String> {
    ENTITY_ID.captures(trim(expr)).map(|m| m[1].to_string())
}

fn entity_uid(expr: &str) -> Option<String> {
    ENTITY_UID.captures(trim(expr)).map(|m| format!("{}::{}", &m[1], &m[2]))
}

fn to_literal(expr: &str) -> Option<Value> {
    let s = trim(expr);
    if let Some(m) = STR_LIT.captures(s) {
        return Some(json!(&m[1]));
    }
    if s == "true" {
        return Some(json!(true));
    }
    if s == "false" {
        return Some(json!(false));
    }
    if NUM_LIT.is_match(s) {
        return Some(number(s));
    }
    entity_uid(s).map(|u| json!(u))
}

fn escape_glob_literal(ch: char, out: &mut String) {
    if matches!(ch, '*' | '?' | '\\') {
        out.push('\\');
    }
    out.push(ch);
}

/// A Cedar `like` pattern (only `*` is a wildcard; `\*` a literal star) as the PCA glob.
fn cedar_like_to_glob(inner: &str) -> String {
    let cs: Vec<char> = inner.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cs.len() {
        let ch = cs[i];
        if ch == '\\' {
            match cs.get(i + 1) {
                Some('*') => {
                    out.push_str("\\*");
                    i += 2;
                }
                Some(&n) => {
                    escape_glob_literal(n, &mut out);
                    i += 2;
                }
                None => {
                    out.push_str("\\\\");
                    i += 1;
                }
            }
            continue;
        }
        if ch == '*' {
            out.push('*');
        } else {
            escape_glob_literal(ch, &mut out);
        }
        i += 1;
    }
    out
}

// ---- Cedar evaluation-error semantics: the guard that makes a policy apply only when no absent attribute is read -----------------

fn guarded_paths(field: Option<&str>) -> Vec<String> {
    match field {
        Some(f)
            if !matches!(f, "subject.id" | "action.verb" | "action.resource" | "env")
                && !f.starts_with("env.entity_parents")
                && (f.starts_with("subject.") || f.starts_with("env.")) =>
        {
            vec![f.to_string()]
        }
        _ => vec![],
    }
}

fn all_of(mut xs: Vec<Value>) -> Value {
    if xs.len() == 1 {
        xs.remove(0)
    } else {
        json!({ "all_of": xs })
    }
}

fn any_of(mut xs: Vec<Value>) -> Value {
    if xs.len() == 1 {
        xs.remove(0)
    } else {
        json!({ "any_of": xs })
    }
}

/// "Evaluating this expression raises no Cedar error", as a condition (`None` = it cannot).
fn no_error(c: &Value, depth: usize) -> R<Option<Value>> {
    if depth > MAX_FRAMES {
        return Err(STACK.into());
    }
    if let Some(inner) = c.get("not") {
        return no_error(inner, depth + 1);
    }
    let group = if c.get("all_of").is_some() {
        Some(("all_of", true))
    } else if c.get("any_of").is_some() {
        Some(("any_of", false))
    } else {
        None
    };
    if let Some((key, is_and)) = group {
        let empty = Vec::new();
        let kids = c[key].as_array().unwrap_or(&empty);
        let mut acc: Option<Value> = None;
        for kid in kids.iter().rev() {
            let n = no_error(kid, depth + 1)?;
            let cont = acc.as_ref().map(|a| any_of(vec![if is_and { json!({ "not": kid }) } else { kid.clone() }, a.clone()]));
            acc = match (n, cont) {
                (None, cont) => cont,
                (Some(n), None) => Some(n),
                (Some(n), Some(cont)) => Some(all_of(vec![n, cont])),
            };
        }
        return Ok(acc);
    }
    let field = c.get("field").and_then(Value::as_str);
    if c.get("op").and_then(Value::as_str) == Some("exists") {
        if let Some(f) = field {
            let base = LAST_SEG.replace(f, "").into_owned();
            let deep = base.split('.').count() >= if base.starts_with("env.resource") { 3 } else { 2 };
            let needs: Vec<Value> = if deep { guarded_paths(Some(base.as_str())).iter().map(|p| exists(p)).collect() } else { vec![] };
            return Ok(if needs.is_empty() { None } else { Some(all_of(needs)) });
        }
    }
    let mut needs: Vec<Value> = guarded_paths(field).iter().map(|p| exists(p)).collect();
    needs.extend(guarded_paths(c.get("ref").and_then(Value::as_str)).iter().map(|p| exists(p)));
    Ok(if needs.is_empty() { None } else { Some(all_of(needs)) })
}
