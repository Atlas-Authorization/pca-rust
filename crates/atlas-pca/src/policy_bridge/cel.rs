//! Strict CEL: one boolean expression as one PCA condition, or a rejection naming the construct (there is no best-effort mode).
//! Positions (`at`) are UTF-16 code-unit offsets, as in the reference.
use super::*;

const MAX_EXPR: usize = 4096;
const CEL_MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 256;
const MAX_LIST: usize = 64;
const MAX_STR: usize = 256;
const FORBIDDEN: [&str; 3] = ["__proto__", "constructor", "prototype"];
const PUNCT: [&str; 16] = ["&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-"];
const RELOPS: [&str; 6] = ["==", "!=", "<", "<=", ">", ">="];
const REJECTED_FUNCS: &str = "size matches exists all exists_one map filter int uint double string bytes bool duration type dyn min max getHours getDayOfWeek getMinutes getSeconds getFullYear getMonth getDate getDayOfMonth getDayOfYear getMilliseconds extract format lowerAscii upperAscii trim split join replace substring indexOf lastIndexOf charAt isIpv4 inIpRange cidr ip isCIDR containsIp url quantity semver optional";
const MAX_SAFE: i64 = 9_007_199_254_740_991;

static CEL_IDENT: LazyLock<Regex> = LazyLock::new(|| rx_full("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*"));
static PCA_PATH: LazyLock<Regex> = LazyLock::new(|| rx_full("(?:action|subject|env)(?:\\.[A-Za-z_][A-Za-z0-9_]*)+"));
static TS: LazyLock<Regex> = LazyLock::new(|| rx_full("([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\\.([0-9]{1,3}))?Z"));

fn unsupported_char(c: char) -> Option<&'static str> {
    Some(match c {
        '+' => "arithmetic (+)",
        '*' => "arithmetic (*)",
        '/' => "arithmetic (/)",
        '%' => "arithmetic (%)",
        '?' => "the conditional operator",
        ':' => "the conditional operator / map literal",
        '{' | '}' => "map or message literal",
        '@' => "@",
        '&' => "bitwise &",
        '|' => "bitwise |",
        '^' => "^",
        '~' => "~",
        '=' => "assignment",
        '`' => "quoted identifier",
        _ => return None,
    })
}

/// A rejection: `{ok: false, code, message, at}`.
struct Reject {
    code: &'static str,
    message: String,
    at: i64,
}

type R<T> = Result<T, Reject>;

fn rej<T>(code: &'static str, message: impl Into<String>, at: i64) -> R<T> {
    Err(Reject { code, message: message.into(), at })
}

fn cel_error(e: &Reject) -> Value {
    json!({ "ok": false, "code": e.code, "message": e.message, "at": e.at })
}

#[derive(Clone, PartialEq)]
enum K {
    Id,
    Int,
    Str,
    P,
}

#[derive(Clone)]
struct Tok {
    k: K,
    v: String,
    at: i64,
}

fn is_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn lex(cs: &[char], off: &[i64]) -> R<Vec<Tok>> {
    let n = cs.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let c = cs[i];
        if matches!(c, ' ' | '\t' | '\n' | '\r') {
            i += 1;
            continue;
        }
        if c == '/' && cs.get(i + 1) == Some(&'/') {
            return rej("unsupported", "comments", off[i]);
        }
        if is_letter(c) {
            let mut j = i + 1;
            while j < n && (is_letter(cs[j]) || cs[j].is_ascii_digit()) {
                j += 1;
            }
            let w: String = cs[i..j].iter().collect();
            if matches!(w.as_str(), "r" | "b" | "R" | "B") && matches!(cs.get(j), Some('"') | Some('\'')) {
                return rej("unsupported", format!("{} literal", if w.eq_ignore_ascii_case("r") { "raw string" } else { "bytes" }), off[i]);
            }
            out.push(Tok { k: K::Id, v: w, at: off[i] });
            i = j;
            continue;
        }
        if c.is_ascii_digit() {
            let mut j = i;
            while j < n && cs[j].is_ascii_digit() {
                j += 1;
            }
            let nxt = cs.get(j).copied();
            if nxt == Some('.') && cs.get(j + 1).is_some_and(|d| d.is_ascii_digit()) {
                return rej("unsupported", "double literal", off[i]);
            }
            if matches!(nxt, Some('e') | Some('E')) {
                return rej("unsupported", "double literal", off[i]);
            }
            if matches!(nxt, Some('u') | Some('U')) {
                return rej("unsupported", "unsigned integer literal", off[i]);
            }
            if matches!(nxt, Some('x') | Some('X')) {
                return rej("unsupported", "hexadecimal literal", off[i]);
            }
            let w: String = cs[i..j].iter().collect();
            if w.len() > 1 && w.starts_with('0') {
                return rej("unsupported", "integer literal with a leading zero", off[i]);
            }
            out.push(Tok { k: K::Int, v: w, at: off[i] });
            i = j;
            continue;
        }
        if c == '"' || c == '\'' {
            if cs.len() >= i + 3 && cs[i + 1] == c && cs[i + 2] == c {
                return rej("unsupported", "triple-quoted string", off[i]);
            }
            let mut j = i + 1;
            let mut s = String::new();
            loop {
                let d = cs.get(j).copied();
                match d {
                    None | Some('\n') | Some('\r') => return rej("syntax", "unterminated string", off[i]),
                    Some(d) if d == c => break,
                    Some('\\') => {
                        let e = cs.get(j + 1).copied();
                        let mapped = match e {
                            Some('\\') => '\\',
                            Some('"') => '"',
                            Some('\'') => '\'',
                            Some('n') => '\n',
                            Some('t') => '\t',
                            Some('r') => '\r',
                            _ => {
                                let shown = e.map(String::from).unwrap_or_default();
                                return rej("unsupported", format!("string escape \\{shown}"), off[j]);
                            }
                        };
                        s.push(mapped);
                        j += 2;
                    }
                    Some(d) => {
                        s.push(d);
                        j += 1;
                    }
                }
            }
            if s.encode_utf16().count() > MAX_STR {
                return rej("too_complex", format!("string literal longer than {MAX_STR}"), off[i]);
            }
            out.push(Tok { k: K::Str, v: s, at: off[i] });
            i = j + 1;
            continue;
        }
        let p = PUNCT.iter().find(|x| {
            let xs: Vec<char> = x.chars().collect();
            cs.len() >= i + xs.len() && cs[i..i + xs.len()] == xs[..]
        });
        match p {
            None => {
                return match unsupported_char(c) {
                    Some(m) => rej("unsupported", m, off[i]),
                    None => rej("syntax", format!("unexpected character '{c}'"), off[i]),
                }
            }
            Some(p) => {
                out.push(Tok { k: K::P, v: p.to_string(), at: off[i] });
                i += p.len();
            }
        }
    }
    Ok(out)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn parse_timestamp(s: &str, at: i64) -> R<i64> {
    let m = match TS.captures(s) {
        Some(m) => m,
        None => return rej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at),
    };
    let (date, time) = m[1].split_once('T').unwrap_or(("", ""));
    let dp: Vec<i64> = date.split('-').map(|x| x.parse().unwrap_or(0)).collect();
    let tp: Vec<i64> = time.split(':').map(|x| x.parse().unwrap_or(0)).collect();
    let (y, mo, d) = (dp[0], dp[1], dp[2]);
    let (h, mi, sec) = (tp[0], tp[1], tp[2]);
    let ms: i64 = m.get(2).map_or("", |x| x.as_str()).chars().chain(std::iter::repeat('0')).take(3).collect::<String>().parse().unwrap_or(0);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !((1..=12).contains(&mo) && d >= 1 && d <= dim[(mo - 1) as usize] && h <= 23 && mi <= 59 && sec <= 59) {
        return rej("unsupported", "timestamp() is not a real instant", at);
    }
    Ok((((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + sec) * 1000 + ms)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    nodes: usize,
    src_len: i64,
}

fn tstr<'a>(n: &'a Value) -> &'a str {
    n["t"].as_str().unwrap_or("")
}

impl Parser {
    fn peek(&self) -> Option<Tok> {
        self.toks.get(self.pos).cloned()
    }

    fn is_p(&self, v: &str) -> bool {
        self.toks.get(self.pos).is_some_and(|t| t.k == K::P && t.v == v)
    }

    fn eat(&mut self, v: &str) -> bool {
        if self.is_p(v) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn need(&mut self, v: &str) -> R<()> {
        if self.eat(v) {
            return Ok(());
        }
        let at = self.peek().map_or(self.src_len, |t| t.at);
        rej("syntax", format!("expected '{v}'"), at)
    }

    fn tick(&mut self, at: i64) -> R<()> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return rej("too_complex", format!("more than {MAX_NODES} nodes"), at);
        }
        Ok(())
    }

    fn expr(&mut self, d: usize) -> R<Value> {
        if d > CEL_MAX_DEPTH {
            let at = self.peek().map_or(0, |t| t.at);
            return rej("too_complex", format!("nesting deeper than {CEL_MAX_DEPTH}"), at);
        }
        self.or_(d)
    }

    fn or_(&mut self, d: usize) -> R<Value> {
        let mut left = self.and_(d)?;
        while self.is_p("||") {
            let at = self.peek().map_or(0, |t| t.at);
            self.pos += 1;
            self.tick(at)?;
            let r = self.and_(d)?;
            left = json!({ "t": "or", "l": left, "r": r, "at": at });
        }
        Ok(left)
    }

    fn and_(&mut self, d: usize) -> R<Value> {
        let mut left = self.rel(d)?;
        while self.is_p("&&") {
            let at = self.peek().map_or(0, |t| t.at);
            self.pos += 1;
            self.tick(at)?;
            let r = self.rel(d)?;
            left = json!({ "t": "and", "l": left, "r": r, "at": at });
        }
        Ok(left)
    }

    fn is_relop(t: &Tok) -> bool {
        (t.k == K::P && RELOPS.contains(&t.v.as_str())) || (t.k == K::Id && t.v == "in")
    }

    fn rel(&mut self, d: usize) -> R<Value> {
        let left = self.unary(d)?;
        let t = match self.peek() {
            Some(t) if Self::is_relop(&t) => t,
            _ => return Ok(left),
        };
        self.pos += 1;
        self.tick(t.at)?;
        let r = self.unary(d)?;
        let n = json!({ "t": "rel", "op": t.v, "l": left, "r": r, "at": t.at });
        if let Some(u) = self.peek() {
            if Self::is_relop(&u) {
                return rej("unsupported", "chained comparison", u.at);
            }
        }
        Ok(n)
    }

    fn unary(&mut self, d: usize) -> R<Value> {
        if let Some(t) = self.peek() {
            if t.k == K::P && t.v == "!" {
                self.pos += 1;
                self.tick(t.at)?;
                if d + 1 > CEL_MAX_DEPTH {
                    return rej("too_complex", format!("nesting deeper than {CEL_MAX_DEPTH}"), t.at);
                }
                let e = self.unary(d + 1)?;
                return Ok(json!({ "t": "not", "e": e, "at": t.at }));
            }
            if t.k == K::P && t.v == "-" {
                let nx = match self.toks.get(self.pos + 1) {
                    Some(nx) if nx.k == K::Int => nx.clone(),
                    _ => return rej("unsupported", "unary minus on a non-literal", t.at),
                };
                self.pos += 2;
                return self.int_node(&format!("-{}", nx.v), t.at);
            }
        }
        self.member(d)
    }

    fn int_node(&mut self, text: &str, at: i64) -> R<Value> {
        self.tick(at)?;
        match text.parse::<i64>() {
            Ok(v) if v.abs() <= MAX_SAFE => Ok(json!({ "t": "int", "v": v, "at": at })),
            _ => rej("unsupported", "integer literal outside the safe-integer range", at),
        }
    }

    fn args(&mut self, d: usize) -> R<Vec<Value>> {
        let mut a = Vec::new();
        if !self.is_p(")") {
            a.push(self.expr(d + 1)?);
            while self.eat(",") {
                a.push(self.expr(d + 1)?);
            }
        }
        self.need(")")?;
        Ok(a)
    }

    fn member(&mut self, d: usize) -> R<Value> {
        let mut n = self.primary(d)?;
        while self.is_p(".") {
            let dot = self.peek().map_or(0, |t| t.at);
            self.pos += 1;
            let ident = match self.peek() {
                Some(t) if t.k == K::Id => t,
                _ => return rej("syntax", "expected a name after '.'", dot),
            };
            self.pos += 1;
            if self.is_p("(") {
                self.pos += 1;
                let mut a = self.args(d)?;
                if !matches!(ident.v.as_str(), "startsWith" | "endsWith" | "contains") {
                    return rej("unsupported", format!("method '{}'", ident.v), ident.at);
                }
                if a.len() != 1 {
                    return rej("syntax", format!("'{}' takes one argument", ident.v), ident.at);
                }
                self.tick(ident.at)?;
                n = json!({ "t": "method", "target": n, "fn": ident.v, "arg": a.remove(0), "at": ident.at });
            } else {
                if tstr(&n) != "var" {
                    return rej("unsupported", "field selection on something that is not a declared variable", dot);
                }
                let name = format!("{}.{}", n["name"].as_str().unwrap_or(""), ident.v);
                n["name"] = json!(name);
            }
        }
        if self.is_p("[") {
            let at = self.peek().map_or(0, |t| t.at);
            return rej("unsupported", "index operator", at);
        }
        Ok(n)
    }

    fn primary(&mut self, d: usize) -> R<Value> {
        let t = match self.peek() {
            Some(t) => t,
            None => return rej("syntax", "unexpected end of expression", self.src_len),
        };
        if t.k == K::Int {
            self.pos += 1;
            return self.int_node(&t.v, t.at);
        }
        if t.k == K::Str {
            self.pos += 1;
            self.tick(t.at)?;
            return Ok(json!({ "t": "str", "v": t.v, "at": t.at }));
        }
        if t.k == K::P && t.v == "(" {
            self.pos += 1;
            let e = self.expr(d + 1)?;
            self.need(")")?;
            return Ok(e);
        }
        if t.k == K::P && t.v == "[" {
            self.pos += 1;
            let mut items = Vec::new();
            if !self.is_p("]") {
                loop {
                    if items.len() >= MAX_LIST {
                        return rej("too_complex", format!("list longer than {MAX_LIST}"), t.at);
                    }
                    items.push(self.expr(d + 1)?);
                    if !self.eat(",") {
                        break;
                    }
                }
            }
            self.need("]")?;
            self.tick(t.at)?;
            return Ok(json!({ "t": "list", "items": items, "at": t.at }));
        }
        if t.k == K::Id {
            self.pos += 1;
            if t.v == "true" || t.v == "false" {
                self.tick(t.at)?;
                let b = t.v == "true";
                return Ok(json!({ "t": "bool", "v": b, "at": t.at }));
            }
            if t.v == "null" {
                return rej("unsupported", "null", t.at);
            }
            if self.is_p("(") {
                self.pos += 1;
                let a = self.args(d)?;
                if t.v == "has" {
                    if a.len() != 1 || tstr(&a[0]) != "var" {
                        return rej("syntax", "has() takes one declared variable", t.at);
                    }
                    self.tick(t.at)?;
                    return Ok(json!({ "t": "has", "e": a[0], "at": t.at }));
                }
                if t.v == "timestamp" {
                    if a.len() != 1 || tstr(&a[0]) != "str" {
                        return rej("unsupported", "timestamp() of a non-literal", t.at);
                    }
                    let v = parse_timestamp(a[0]["v"].as_str().unwrap_or(""), t.at)?;
                    return Ok(json!({ "t": "ts", "v": v, "at": t.at }));
                }
                let known = REJECTED_FUNCS.split(' ').any(|f| f == t.v);
                return rej("unsupported", format!("{} '{}'", if known { "function" } else { "unknown function" }, t.v), t.at);
            }
            if t.v == "in" {
                return rej("syntax", "unexpected 'in'", t.at);
            }
            self.tick(t.at)?;
            return Ok(json!({ "t": "var", "name": t.v, "at": t.at }));
        }
        rej("syntax", format!("unexpected '{}'", t.v), t.at)
    }
}

fn parse(src: &Value) -> R<Value> {
    let s = match src.as_str() {
        Some(s) if !s.is_empty() => s,
        _ => return rej("syntax", "empty expression", 0),
    };
    let cs: Vec<char> = s.chars().collect();
    let mut off = Vec::with_capacity(cs.len() + 1);
    let mut u = 0i64;
    for c in &cs {
        off.push(u);
        u += c.len_utf16() as i64;
    }
    off.push(u);
    if u as usize > MAX_EXPR {
        return rej("too_complex", format!("expression longer than {MAX_EXPR} characters"), 0);
    }
    let toks = lex(&cs, &off)?;
    let mut p = Parser { toks, pos: 0, nodes: 0, src_len: u };
    let root = p.expr(0)?;
    if let Some(t) = p.peek() {
        return rej("syntax", format!("unexpected '{}'", t.v), t.at);
    }
    Ok(root)
}

/// Parse a CEL expression of the supported subset: `{ok: true, ast}` or `{ok: false, code, message, at}`.
pub fn parse_cel(expression: &Value) -> Value {
    match parse(expression) {
        Ok(ast) => json!({ "ok": true, "ast": ast }),
        Err(e) => cel_error(&e),
    }
}

fn schema_error(s: &Value) -> Option<String> {
    let vars = match s.as_object().and_then(|o| o.get("vars")) {
        Some(Value::Object(v)) => v,
        Some(_) | None if s.is_object() => return Some("the schema needs a vars object".into()),
        _ => return Some("the schema must be an object".into()),
    };
    for name in key_order(vars) {
        let v = &vars[name.as_str()];
        if !CEL_IDENT.is_match(name) || name.split('.').any(|x| FORBIDDEN.contains(&x)) {
            return Some(format!("bad variable name '{name}'"));
        }
        let path = member(v, "path").and_then(Value::as_str);
        let path_ok = path.is_some_and(|p| PCA_PATH.is_match(p) && !p.split('.').any(|x| FORBIDDEN.contains(&x)));
        if !is_obj(v) || !path_ok {
            return Some(format!("variable '{name}' needs a path rooted at action, subject or env"));
        }
        let t = member(v, "type").and_then(Value::as_str);
        if !matches!(t, Some("string" | "int" | "bool" | "timestamp_ms")) {
            return Some(format!("variable '{name}' has an unsupported type"));
        }
        if let Some(o) = member(v, "optional") {
            if !o.is_boolean() {
                return Some(format!("variable '{name}': optional must be a boolean"));
            }
        }
    }
    None
}

fn member<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

enum Op<'a> {
    Var { def: &'a Value, name: String },
    Lit { ty: &'static str, value: Value },
}

impl Op<'_> {
    fn ty(&self) -> &str {
        match self {
            Op::Var { def, .. } => def["type"].as_str().unwrap_or(""),
            Op::Lit { ty, .. } => ty,
        }
    }

    fn is_var(&self) -> bool {
        matches!(self, Op::Var { .. })
    }
}

struct Tr<'a> {
    vars: &'a Map<String, Value>,
    fields: Vec<String>,
}

impl<'a> Tr<'a> {
    fn operand(&self, n: &Value) -> R<Op<'a>> {
        let at = n["at"].as_i64().unwrap_or(0);
        match tstr(n) {
            "var" => {
                let name = n["name"].as_str().unwrap_or("");
                match self.vars.get(name) {
                    Some(def) => Ok(Op::Var { def, name: name.to_string() }),
                    None => rej("unknown_identifier", format!("'{name}' is not declared in the schema"), at),
                }
            }
            "int" => Ok(Op::Lit { ty: "int", value: n["v"].clone() }),
            "str" => Ok(Op::Lit { ty: "string", value: n["v"].clone() }),
            "bool" => Ok(Op::Lit { ty: "bool", value: n["v"].clone() }),
            "ts" => Ok(Op::Lit { ty: "timestamp_ms", value: n["v"].clone() }),
            _ => rej("unsupported", "a computed value as a comparison operand", at),
        }
    }

    fn read(&mut self, o: &Op) -> String {
        let path = match o {
            Op::Var { def, .. } => def["path"].as_str().unwrap_or("").to_string(),
            Op::Lit { .. } => String::new(),
        };
        if !self.fields.contains(&path) {
            self.fields.push(path.clone());
        }
        path
    }

    fn flat<'v>(n: &'v Value, t: &str, out: &mut Vec<&'v Value>) {
        if tstr(n) == t {
            Self::flat(&n["l"], t, out);
            Self::flat(&n["r"], t, out);
        } else {
            out.push(n);
        }
    }

    fn tr(&mut self, n: &Value) -> R<Value> {
        let at = n["at"].as_i64().unwrap_or(0);
        let t = tstr(n);
        if t == "or" || t == "and" {
            let mut parts = Vec::new();
            Self::flat(n, t, &mut parts);
            let mut kids = Vec::new();
            for x in parts {
                kids.push(self.tr(x)?);
            }
            return Ok(if t == "or" { json!({ "any_of": kids }) } else { json!({ "all_of": kids }) });
        }
        if t == "not" {
            return Ok(json!({ "not": self.tr(&n["e"])? }));
        }
        if t == "has" {
            let o = self.operand(&n["e"])?;
            let (def, name) = match &o {
                Op::Var { def, name } => (*def, name.clone()),
                Op::Lit { .. } => return rej("syntax", "has() takes a declared variable", at),
            };
            if def.get("optional") != Some(&json!(true)) {
                return rej(
                    "has_requires_optional",
                    format!("has({name}): mark the variable optional in the schema (its container must always be present)"),
                    at,
                );
            }
            return Ok(json!({ "field": self.read(&o), "op": "exists", "value": true }));
        }
        if t == "var" {
            let o = self.operand(n)?;
            let name = n["name"].as_str().unwrap_or("");
            let hint = if o.is_var() && o.ty() == "bool" { format!(" (write {name} == true)") } else { String::new() };
            return rej("unsupported", format!("a bare variable '{name}' as a condition{hint}"), at);
        }
        if t == "method" {
            let f = n["fn"].as_str().unwrap_or("");
            let tg = self.operand(&n["target"])?;
            if !tg.is_var() || tg.ty() != "string" {
                return rej("type_mismatch", format!("{f} needs a string variable"), at);
            }
            let arg = &n["arg"];
            let lit = arg["v"].as_str().unwrap_or("");
            if tstr(arg) != "str" || lit.is_empty() {
                return rej("unsupported", format!("{f} of anything but a non-empty string literal"), at);
            }
            if f == "startsWith" {
                return Ok(json!({ "field": self.read(&tg), "op": "prefix", "value": lit }));
            }
            let mut esc = String::new();
            for c in lit.chars() {
                if matches!(c, '\\' | '*' | '?') {
                    esc.push('\\');
                }
                esc.push(c);
            }
            let glob = if f == "endsWith" { format!("*{esc}") } else { format!("*{esc}*") };
            if glob.encode_utf16().count() > 512 {
                return rej("too_complex", "literal too long for a glob", at);
            }
            return Ok(json!({ "field": self.read(&tg), "op": "like", "value": glob }));
        }
        if t == "rel" {
            let op = n["op"].as_str().unwrap_or("");
            if op == "in" {
                let left = self.operand(&n["l"])?;
                if !left.is_var() {
                    return rej("constant_expression", "the left side of \"in\" must be a declared variable", at);
                }
                let list = &n["r"];
                let items_node = list["items"].as_array();
                if tstr(list) != "list" || items_node.map_or(true, |a| a.is_empty()) {
                    return rej("unsupported", "\"in\" against anything but a non-empty list literal", at);
                }
                let mut items = Vec::new();
                for x in items_node.map(|a| a.as_slice()).unwrap_or(&[]) {
                    items.push(self.operand(x)?);
                }
                if items.iter().any(|i| i.is_var() || i.ty() != left.ty()) {
                    return rej("type_mismatch", format!("list items must be {} literals", left.ty()), at);
                }
                let values: Vec<Value> = items
                    .iter()
                    .map(|i| match i {
                        Op::Lit { value, .. } => value.clone(),
                        Op::Var { .. } => Value::Null,
                    })
                    .collect();
                return Ok(json!({ "field": self.read(&left), "op": "in", "value": values }));
            }
            let left = self.operand(&n["l"])?;
            let right = self.operand(&n["r"])?;
            if !left.is_var() && !right.is_var() {
                return rej("constant_expression", "a comparison of two literals", at);
            }
            if left.ty() != right.ty() {
                return rej("type_mismatch", format!("{} against {}", left.ty(), right.ty()), at);
            }
            if op != "==" && op != "!=" && left.ty() == "bool" {
                return rej("type_mismatch", "ordering of booleans", at);
            }
            let (pca_op, flip) = match op {
                "==" => ("eq", "eq"),
                "!=" => ("ne", "ne"),
                "<" => ("lt", "gt"),
                "<=" => ("lte", "gte"),
                ">" => ("gt", "lt"),
                _ => ("gte", "lte"),
            };
            return Ok(match (&left, &right) {
                (Op::Var { .. }, Op::Var { .. }) => {
                    let (f, r) = (self.read(&left), self.read(&right));
                    json!({ "field": f, "op": pca_op, "ref": r })
                }
                (Op::Var { .. }, Op::Lit { value, .. }) => json!({ "field": self.read(&left), "op": pca_op, "value": value }),
                (Op::Lit { value, .. }, _) => json!({ "field": self.read(&right), "op": flip, "value": value }),
            });
        }
        rej("constant_expression", "a bare constant is not a condition", at)
    }
}

/// ONE boolean CEL expression as a PCA condition, or a rejection naming the construct (there is no best-effort mode):
/// `{ok: true, condition, fields}` or `{ok: false, code, message, at}`. `schema` is `{vars: {name: {path, type, optional?}}}`.
pub fn cel_to_condition(expression: &Value, schema: &Value) -> Value {
    if let Some(m) = schema_error(schema) {
        return json!({ "ok": false, "code": "bad_schema", "message": m, "at": 0 });
    }
    let ast = match parse(expression) {
        Ok(a) => a,
        Err(e) => return cel_error(&e),
    };
    let vars = match schema.get("vars").and_then(Value::as_object) {
        Some(v) => v,
        None => return json!({ "ok": false, "code": "bad_schema", "message": "the schema needs a vars object", "at": 0 }),
    };
    let mut tr = Tr { vars, fields: Vec::new() };
    let condition = match tr.tr(&ast) {
        Ok(c) => c,
        Err(e) => return cel_error(&e),
    };
    if tr.fields.is_empty() {
        return cel_error(&Reject { code: "constant_expression", message: "the expression reads no variable".into(), at: 0 });
    }
    let mut fields = tr.fields;
    fields.sort_by(cmp16);
    json!({ "ok": true, "condition": condition, "fields": fields })
}

/// One CEL expression as a permit predicate for `scope.verb` (and optionally `scope.resource`). `Err` is where the reference throws.
pub fn cel_to_predicate(expression: &Value, schema: &Value, scope: &Value) -> Result<Value, String> {
    if scope.is_null() {
        return Err("cannot read properties of null (reading 'verb')".into());
    }
    let r = cel_to_condition(expression, schema);
    if r["ok"] != json!(true) {
        return Ok(r);
    }
    let mut p = Map::new();
    if let Some(v) = member(scope, "verb") {
        p.insert("verb".into(), v.clone());
    }
    if let Some(v) = member(scope, "resource") {
        p.insert("resource".into(), v.clone());
    }
    p.insert("where".into(), json!([r["condition"].clone()]));
    Ok(json!({ "ok": true, "predicate": Value::Object(p), "fields": r["fields"].clone() }))
}

/// A batch of named CEL expressions: every one is translated or REPORTED; one rejection makes `report.errors` non-empty, and `decide`
/// then denies everything (an incomplete import never grants). `Err` is where the reference throws.
pub fn cel_conditions_to_pca(items: &Value, schema: &Value) -> Result<Value, String> {
    let list = items.as_array().ok_or("items is not iterable")?;
    let (mut predicates, mut translated, mut errors) = (Vec::new(), Vec::new(), Vec::new());
    for it in list {
        let o = it.as_object().ok_or("cannot read properties of a non-object item")?;
        let mut scope = Map::new();
        if let Some(v) = o.get("verb") {
            scope.insert("verb".into(), v.clone());
        }
        if let Some(v) = o.get("resource") {
            scope.insert("resource".into(), v.clone());
        }
        let r = cel_to_predicate(o.get("expression").unwrap_or(&Value::Null), schema, &Value::Object(scope))?;
        let name = js_text(o.get("name"));
        if r["ok"] == json!(true) {
            let fields: Vec<&str> = r["fields"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            translated.push(format!("{name}: translated exactly (reads {})", fields.join(", ")));
            predicates.push(r["predicate"].clone());
        } else {
            errors.push(format!("{name}: rejected ({}) at {}: {}", r["code"].as_str().unwrap_or(""), r["at"], r["message"].as_str().unwrap_or("")));
        }
    }
    Ok(
        json!({ "predicates": predicates, "denies": [], "caveats": [], "report": { "source": "cel", "translated": translated, "skipped": [], "errors": errors } }),
    )
}
