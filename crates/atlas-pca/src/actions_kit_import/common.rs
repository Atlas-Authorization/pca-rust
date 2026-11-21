//! What every action importer shares (limits, result shapes, text hygiene, verb naming, the bounded `$ref` resolver, the JSON Schema to
//! ParamDef flattening and the single place a draft ActionDef is assembled, always `unreviewed`). Sources are parsed JSON values;
//! an importer returns `{"defs", "todo", "source"}`. The reference's JavaScript semantics (UTF-16 lengths, property reads on any
//! value, spread of non-objects) are reproduced where an output depends on them. A Rust `String` cannot hold a lone surrogate, so
//! the surrogate clean-up of the reference has nothing to do here.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use unicode_normalization::{is_nfc, UnicodeNormalization};

use crate::action_schema::is_js_ws;
pub use crate::actions::ActionKitError;
use crate::actions::{utf16_len, validate_def};

pub type R<T> = Result<T, ActionKitError>;

pub fn kerr(code: &str, message: impl Into<String>) -> ActionKitError {
    ActionKitError { code: code.into(), message: message.into() }
}
/// A JavaScript runtime TypeError of the reference (a refusal with no reference code).
pub fn type_err(message: impl Into<String>) -> ActionKitError {
    kerr("type_error", message)
}

pub const MAX_DEF_PARAMS: usize = 64;
pub const MAX_TITLE_BYTES: usize = 120;
pub const MAX_DESCRIPTION_BYTES: usize = 1024;
pub const MAX_PARAM_PATH_DEPTH: usize = 3;
pub const EFFECTS: [&str; 12] = ["read", "create", "update", "delete", "send", "pay", "exec", "privilege", "export", "publish", "provision", "sign"];
pub const CORE_ROLES: [&str; 26] = [
    "money.amount",
    "money.currency",
    "money.fee",
    "party.payee",
    "party.payer",
    "contact.email",
    "contact.phone",
    "contact.address",
    "person.name",
    "person.dob",
    "person.national_id",
    "credential.secret",
    "credential.token",
    "credential.key",
    "path.fs",
    "query.sql",
    "query.search",
    "code.source",
    "code.command",
    "url.target",
    "text.message",
    "text.public",
    "time.not_before",
    "time.not_after",
    "count.limit",
    "bytes.size",
];

fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

// ---- small value helpers ----------------------------------------------------------------------------------------------------

pub fn is_obj(v: &Value) -> bool {
    v.is_object()
}
pub fn is_str(v: &Value) -> bool {
    v.is_string()
}
/// `o[k]` for a JSON value: an own member of an object, else undefined (an array or scalar has no such member here).
pub fn g<'a>(o: &'a Value, k: &str) -> Option<&'a Value> {
    o.as_object().and_then(|m| m.get(k))
}
/// `g` for an optional receiver.
pub fn go<'a>(o: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    o.and_then(|x| g(x, k))
}
pub fn gstr<'a>(o: &'a Value, k: &str) -> Option<&'a str> {
    g(o, k).and_then(Value::as_str)
}
/// JavaScript truthiness of a (possibly undefined) JSON value.
pub fn jtruthy(v: Option<&Value>) -> bool {
    crate::oauth::truthy(v)
}
/// `String(v)`; `undefined` for an absent value.
pub fn js_str(v: &Value) -> String {
    crate::oauth::js_str(v)
}
pub fn js_str_opt(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), js_str)
}
pub fn s(x: &str) -> Value {
    Value::String(x.to_string())
}
pub fn svec(xs: &[String]) -> Value {
    Value::Array(xs.iter().map(|x| Value::String(x.clone())).collect())
}
pub fn is_true(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}
pub fn is_num(v: &Value) -> bool {
    v.is_number()
}
pub fn as_f(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}
/// `Number.isSafeInteger` over a JSON value.
pub fn is_safe_integer(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => {
            if let Some(i) = n.as_i64() {
                i.unsigned_abs() <= (1u64 << 53) - 1
            } else if let Some(u) = n.as_u64() {
                u <= (1u64 << 53) - 1
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                f.is_finite() && f.fract() == 0.0 && f.abs() <= 9007199254740991.0
            }
        }
        _ => false,
    }
}
/// `int(v)` of a safe-integer JSON number.
pub fn to_i64(v: &Value) -> i64 {
    v.as_i64().unwrap_or_else(|| v.as_f64().unwrap_or(0.0) as i64)
}
/// Member order of an object by UTF-8 byte order (the reference's `utf8` key sort).
pub fn sorted_keys(m: &Map<String, Value>) -> Vec<String> {
    let mut ks: Vec<String> = m.keys().cloned().collect();
    ks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ks
}
pub fn uniq_strs(xs: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    xs.into_iter().filter(|x| seen.insert(x.clone())).collect()
}
/// `{...v}`: an object's members, an array's / string's indexed members, nothing for a scalar.
pub fn spread_obj(v: Option<&Value>) -> Map<String, Value> {
    match v {
        Some(Value::Object(m)) => m.clone(),
        Some(Value::Array(a)) => a.iter().enumerate().map(|(i, x)| (i.to_string(), x.clone())).collect(),
        Some(Value::String(t)) => t.encode_utf16().enumerate().map(|(i, u)| (i.to_string(), Value::String(String::from_utf16_lossy(&[u])))).collect(),
        _ => Map::new(),
    }
}
/// `[...v]`: an array or a string (by code point); anything else is not iterable (a TypeError).
pub fn spread_arr(v: Option<&Value>) -> R<Vec<Value>> {
    match v {
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(Value::String(t)) => Ok(t.chars().map(|c| Value::String(c.to_string())).collect()),
        _ => Err(type_err("value is not iterable")),
    }
}

// ---- limits -----------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_bytes: i64,
    pub max_ops: i64,
    pub max_json_depth: i64,
    pub max_nodes: i64,
    pub max_ref_nodes: i64,
    pub max_ref_depth: i64,
}
impl Limits {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        for (k, v) in self.pairs() {
            m.insert(k.into(), Value::from(v));
        }
        Value::Object(m)
    }
    fn pairs(&self) -> [(&'static str, i64); 6] {
        [
            ("max_bytes", self.max_bytes),
            ("max_ops", self.max_ops),
            ("max_json_depth", self.max_json_depth),
            ("max_nodes", self.max_nodes),
            ("max_ref_nodes", self.max_ref_nodes),
            ("max_ref_depth", self.max_ref_depth),
        ]
    }
}
pub const DEFAULT_IMPORT_LIMITS: Limits =
    Limits { max_bytes: 64 * 1024 * 1024, max_ops: 20_000, max_json_depth: 64, max_nodes: 6_000_000, max_ref_nodes: 20_000, max_ref_depth: 8 };
pub const HARD_IMPORT_LIMITS: Limits =
    Limits { max_bytes: 256 * 1024 * 1024, max_ops: 50_000, max_json_depth: 128, max_nodes: 20_000_000, max_ref_nodes: 200_000, max_ref_depth: 16 };

/// `resolveLimits(over)`: `over` is any value (only an object's own members count).
pub fn resolve_limits(over: Option<&Value>) -> R<Limits> {
    let mut out = DEFAULT_IMPORT_LIMITS;
    let hard = HARD_IMPORT_LIMITS;
    let slots: [(&str, &mut i64, i64); 6] = [
        ("max_bytes", &mut out.max_bytes, hard.max_bytes),
        ("max_ops", &mut out.max_ops, hard.max_ops),
        ("max_json_depth", &mut out.max_json_depth, hard.max_json_depth),
        ("max_nodes", &mut out.max_nodes, hard.max_nodes),
        ("max_ref_nodes", &mut out.max_ref_nodes, hard.max_ref_nodes),
        ("max_ref_depth", &mut out.max_ref_depth, hard.max_ref_depth),
    ];
    for (k, slot, hardv) in slots {
        let Some(v) = over.and_then(|o| g(o, k)) else { continue };
        if !is_safe_integer(Some(v)) || as_f(v) < 1.0 {
            return Err(kerr("bad_limit", format!("limit {k} must be a positive safe integer")));
        }
        *slot = to_i64(v).min(hardv);
    }
    Ok(out)
}

fn utf8_of(t: &str) -> usize {
    t.len()
}

pub fn text_size_check(text: &Value, lim: &Limits) -> R<()> {
    let Some(t) = text.as_str() else { return Err(kerr("bad_source", "the source must be text")) };
    if (utf16_len(t) as i64) * 3 > lim.max_bytes && utf8_of(t) as i64 > lim.max_bytes {
        return Err(kerr("import_limit", format!("the source is larger than {} bytes", lim.max_bytes)));
    }
    Ok(())
}

/// Walk a parsed source iteratively; refuse anything too deep or large. Returns the node count.
pub fn check_parsed(root: &Value, lim: &Limits) -> R<i64> {
    let (mut nodes, mut size) = (0i64, 0i64);
    let mut stack: Vec<(&Value, i64)> = vec![(root, 0)];
    while let Some((v, d)) = stack.pop() {
        nodes += 1;
        if nodes > lim.max_nodes {
            return Err(kerr("import_limit", format!("the source has more than {} nodes", lim.max_nodes)));
        }
        if d > lim.max_json_depth {
            return Err(kerr("import_limit", format!("the source nests deeper than {}", lim.max_json_depth)));
        }
        match v {
            Value::Null | Value::Bool(_) => size += 4,
            Value::Number(_) => size += 8,
            Value::String(t) => size += utf16_len(t) as i64,
            Value::Array(a) => {
                size += 2 + a.len() as i64;
                for x in a {
                    stack.push((x, d + 1));
                }
            }
            Value::Object(m) => {
                for (k, x) in m {
                    size += utf16_len(k) as i64 + 4;
                    stack.push((x, d + 1));
                }
            }
        }
        if size > lim.max_bytes {
            return Err(kerr("import_limit", format!("the source is larger than {} bytes", lim.max_bytes)));
        }
    }
    Ok(nodes)
}

// ---- result types and context -----------------------------------------------------------------------------------------------

pub const IMPORT_KINDS: [&str; 6] = ["openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema"];
pub const DEFAULT_EXTENSIONS: [&str; 3] = ["x-pca-verb", "x-pca-role", "x-pca-internal"];

pub struct Ctx {
    pub ns: String,
    pub kind: String,
    pub lim: Limits,
    pub todo: Vec<Value>,
    pub source: Map<String, Value>,
    pub ext: HashSet<String>,
    pub root: Value,
    pub verbs: HashSet<String>,
    pub aliases: HashMap<String, String>,
    pub defs: Vec<Value>,
}

/// What an importer reads: a parsed JSON value (text is a JSON string) or raw bytes (a binary descriptor set).
#[derive(Clone, Copy)]
pub enum Source<'a> {
    Json(&'a Value),
    Bytes(&'a [u8]),
}

fn b64u(b: &[u8]) -> String {
    crate::b64_encode(b)
}

fn json_str(t: &str) -> String {
    let mut out = String::from("\"");
    for ch in t.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub(crate) fn lenient(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::String(t) => json_str(t),
        Value::Number(n) => crate::intent_v2::js_number_string(n.as_f64().unwrap_or(f64::NAN)),
        Value::Array(a) => format!("[{}]", a.iter().map(lenient).collect::<Vec<_>>().join(",")),
        Value::Object(m) => format!("{{{}}}", sorted_keys(m).iter().map(|k| format!("{}:{}", json_str(k), lenient(&m[k]))).collect::<Vec<_>>().join(",")),
    }
}

/// base64url(sha256(lenient canonical JSON)): keys by UTF-8 order, numbers as ECMAScript prints them.
pub fn hash_canonical_lenient(v: &Value) -> String {
    b64u(&Sha256::digest(lenient(v).as_bytes()))
}

pub fn new_ctx(kind: &str, source: Source, opts: &Value) -> R<Ctx> {
    let no = Value::Object(Map::new());
    let o = if opts.is_object() { opts } else { &no };
    let ns = match g(o, "ns") {
        Some(Value::String(t)) if is_ns(t) => t.clone(),
        _ => return Err(kerr("bad_ns", "ns must match [a-z][a-z0-9_]{0,31}")),
    };
    let lim = resolve_limits(g(o, "limits"))?;
    let digest = match source {
        Source::Json(Value::String(t)) => {
            text_size_check(&Value::String(t.clone()), &lim)?;
            b64u(&Sha256::digest(t.as_bytes()))
        }
        Source::Bytes(b) => {
            if b.len() as i64 > lim.max_bytes {
                return Err(kerr("import_limit", format!("the source is larger than {} bytes", lim.max_bytes)));
            }
            b64u(&Sha256::digest(b))
        }
        Source::Json(v) => {
            check_parsed(v, &lim)?;
            hash_canonical_lenient(v)
        }
    };
    let now = g(o, "now").filter(|v| !v.is_null());
    let now_v = match now {
        None => 0,
        Some(v) => {
            if !is_safe_integer(Some(v)) || as_f(v) < 0.0 {
                return Err(kerr("bad_opts", "now must be a non-negative integer"));
            }
            to_i64(v)
        }
    };
    let uri = g(o, "uri").filter(|v| !v.is_null());
    let licence = g(o, "licence").filter(|v| !v.is_null());
    let ext: HashSet<String> = match g(o, "allowExtensions").filter(|v| !v.is_null()) {
        None => DEFAULT_EXTENSIONS.iter().map(|x| x.to_string()).collect(),
        Some(Value::String(t)) => t.chars().map(|c| c.to_string()).collect(),
        Some(Value::Array(a)) => {
            if a.iter().any(|x| x.is_array() || x.is_object()) {
                return Err(type_err("unhashable allowExtensions member"));
            }
            a.iter().filter_map(|x| x.as_str().map(String::from)).collect()
        }
        Some(_) => return Err(type_err("allowExtensions is not iterable")),
    };
    let default_uri = Value::String(format!("source:{kind}"));
    let mut src = Map::new();
    src.insert("kind".into(), s(kind));
    src.insert("uri".into(), Value::String(clipv(Some(uri.unwrap_or(&default_uri)), 2048)));
    src.insert("spec_digest".into(), Value::String(digest));
    src.insert(
        "licence".into(),
        Value::String(match licence {
            None => "unknown".to_string(),
            Some(l) => clip_any(l, 128),
        }),
    );
    src.insert("imported_at".into(), Value::from(now_v));
    let root = match &source {
        Source::Json(v) => (*v).clone(),
        Source::Bytes(_) => Value::Null,
    };
    Ok(Ctx { ns, kind: kind.into(), lim, todo: vec![], source: src, ext, root, verbs: HashSet::new(), aliases: HashMap::new(), defs: vec![] })
}

fn is_ns(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

pub fn add_todo(c: &mut Ctx, where_: &str, code: &str, message: &str) {
    // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
    let n = c.todo.len();
    if n < 5000 {
        let mut m = Map::new();
        m.insert("where".into(), Value::String(clip(where_, 200)));
        m.insert("code".into(), s(code));
        m.insert("message".into(), Value::String(clip(message, 400)));
        c.todo.push(Value::Object(m));
    } else if n == 5000 {
        let mut m = Map::new();
        m.insert("where".into(), s("*"));
        m.insert("code".into(), s("todo_truncated"));
        m.insert("message".into(), s("further notes omitted"));
        c.todo.push(Value::Object(m));
    }
}

pub fn finish(c: Ctx) -> Value {
    let mut m = Map::new();
    m.insert("defs".into(), Value::Array(c.defs));
    m.insert("todo".into(), Value::Array(c.todo));
    m.insert("source".into(), Value::Object(c.source));
    Value::Object(m)
}

// ---- text hygiene -----------------------------------------------------------------------------------------------------------

fn is_ctrl(c: char) -> bool {
    matches!(c as u32, 0..=8 | 0xb | 0xc | 0xe..=0x1f | 0x7f..=0x9f | 0x2028 | 0x2029 | 0x202a..=0x202e | 0x2066..=0x2069)
}

pub fn u8len(t: &str) -> usize {
    t.len()
}

/// NFC, no control or bidi-override characters, whitespace collapsed, cut to `max_bytes` at a code point.
pub fn clip(t: &str, max_bytes: usize) -> String {
    let t: String = t.chars().map(|c| if is_ctrl(c) { ' ' } else { c }).nfc().collect();
    let mut collapsed = String::with_capacity(t.len());
    let mut in_ws = false;
    for c in t.chars() {
        if is_js_ws(c) {
            if !in_ws {
                collapsed.push(' ');
            }
            in_ws = true;
        } else {
            collapsed.push(c);
            in_ws = false;
        }
    }
    let t = collapsed.trim_matches(is_js_ws);
    if t.len() <= max_bytes {
        return t.to_string();
    }
    let mut out = String::new();
    let mut n = 0;
    for ch in t.chars() {
        let w = ch.len_utf8();
        if n + w > max_bytes {
            break;
        }
        out.push(ch);
        n += w;
    }
    out.trim_matches(is_js_ws).to_string()
}
/// `clip(x)` of any value: a non-string is the empty string.
pub fn clipv(v: Option<&Value>, max_bytes: usize) -> String {
    match v {
        Some(Value::String(t)) => clip(t, max_bytes),
        _ => String::new(),
    }
}
pub fn clip_any(v: &Value, max_bytes: usize) -> String {
    clipv(Some(v), max_bytes)
}
/// First of the candidates that clips to something.
pub fn first_text(mx: usize, xs: &[Option<&Value>]) -> String {
    for x in xs {
        let t = clipv(*x, mx);
        if !t.is_empty() {
            return t;
        }
    }
    String::new()
}

// ---- tokens and verbs -------------------------------------------------------------------------------------------------------

static CAMEL1: LazyLock<Regex> = LazyLock::new(|| re("([a-z0-9])([A-Z])"));
static CAMEL2: LazyLock<Regex> = LazyLock::new(|| re("([A-Z]+)([A-Z][a-z])"));
static NONALNUM: LazyLock<Regex> = LazyLock::new(|| re("[^a-z0-9]+"));

pub fn tokens_of(name: &str) -> Vec<String> {
    let nfkd: String = name.nfkd().filter(|c| !('\u{300}'..='\u{36f}').contains(c)).collect();
    let a = CAMEL1.replace_all(&nfkd, "$1 $2").into_owned();
    let b = CAMEL2.replace_all(&a, "$1 $2").to_lowercase();
    NONALNUM.split(&b).filter(|t| !t.is_empty()).map(String::from).collect()
}
pub fn tokens_of_v(name: &Value) -> Vec<String> {
    tokens_of(&js_str(name))
}

pub const ACTION_WORDS: [&str; 51] = [
    "get",
    "list",
    "read",
    "fetch",
    "find",
    "search",
    "query",
    "show",
    "describe",
    "create",
    "add",
    "new",
    "make",
    "insert",
    "post",
    "put",
    "set",
    "update",
    "patch",
    "edit",
    "modify",
    "delete",
    "remove",
    "destroy",
    "drop",
    "send",
    "notify",
    "publish",
    "invite",
    "cancel",
    "refund",
    "charge",
    "pay",
    "run",
    "exec",
    "execute",
    "invoke",
    "start",
    "stop",
    "enable",
    "disable",
    "approve",
    "reject",
    "close",
    "open",
    "merge",
    "export",
    "import",
    "upload",
    "download",
    "subscribe",
];
const ACTION_WORDS_TAIL: [&str; 3] = ["unsubscribe", "revoke", "grant"];
fn is_action_word(t: &str) -> bool {
    ACTION_WORDS.contains(&t) || ACTION_WORDS_TAIL.contains(&t) || t == "transfer"
}

fn seg(toks: &[String]) -> String {
    let t = toks.join("_");
    if t.len() <= 32 {
        return t;
    }
    let h: String = b64u(&Sha256::digest(t.as_bytes())).chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    let mut h4: String = h.chars().take(4).collect();
    while h4.len() < 4 {
        h4.push('0');
    }
    format!("{}_{}", &t[..27], h4)
}

/// `[a-z][a-z0-9_]{0,31}(\.[a-z0-9_]{1,32}){min..=max}` over the dotted parts.
fn dotted(t: &str, min: usize, max: usize) -> bool {
    let lcd = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_';
    let mut it = t.split('.');
    let f = it.next().unwrap_or("");
    if f.is_empty() || f.len() > 32 || !f.as_bytes()[0].is_ascii_lowercase() || !f.bytes().all(lcd) {
        return false;
    }
    let rest: Vec<&str> = it.collect();
    rest.len() >= min && rest.len() <= max && rest.iter().all(|p| !p.is_empty() && p.len() <= 32 && p.bytes().all(lcd))
}
pub fn is_verb(t: &str) -> bool {
    dotted(t, 1, 5)
}
pub fn is_alias(t: &str) -> bool {
    dotted(t, 0, 5)
}
pub fn is_resource_type(t: &str) -> bool {
    dotted(t, 0, 4)
}

pub fn verb_of(ns: &str, raw: &Value) -> String {
    verb_of_str(ns, &js_str(raw))
}
pub fn verb_of_str(ns: &str, raw: &str) -> String {
    let parts: Vec<Vec<String>> = raw.split(|c: char| matches!(c, '.' | '/' | ':') || is_js_ws(c)).map(tokens_of).filter(|t| !t.is_empty()).collect();
    let mut segs: Vec<String> = if parts.len() >= 2 {
        parts.iter().map(|p| seg(p)).collect()
    } else {
        let t = parts.first().cloned().unwrap_or_else(|| vec!["op".to_string()]);
        if t.len() >= 2 && is_action_word(&t[0]) {
            vec![seg(&t[1..]), seg(&t[..1])]
        } else if t.len() >= 2 && is_action_word(&t[t.len() - 1]) {
            vec![seg(&t[..t.len() - 1]), seg(&t[t.len() - 1..])]
        } else {
            vec![seg(&t)]
        }
    };
    if segs.len() > 5 {
        let n = segs.len();
        segs = [&segs[..2], &segs[n - 3..]].concat();
    }
    let v = format!("{ns}.{}", segs.join("."));
    if !is_verb(&v) || u8len(&v) > 128 {
        return format!("{ns}.op");
    }
    v
}

pub fn alias_of(raw: &Value, verb: &str) -> Option<String> {
    alias_of_str(&js_str(raw), verb)
}
pub fn alias_of_str(raw: &str, verb: &str) -> Option<String> {
    let a = tokens_of(raw).join("_");
    (!a.is_empty() && a.len() <= 64 && is_alias(&a) && a != verb).then_some(a)
}

pub fn humanize(name: &str) -> String {
    let t = tokens_of(name);
    if t.is_empty() {
        return String::new();
    }
    let first = format!("{}{}", t[0][..1].to_uppercase(), &t[0][1..]);
    std::iter::once(first).chain(t[1..].iter().cloned()).collect::<Vec<_>>().join(" ")
}

pub fn unique_verb(c: &mut Ctx, verb: &str, where_: &str) -> R<String> {
    if !c.verbs.contains(verb) {
        return Ok(verb.to_string());
    }
    for n in 2..100_000 {
        let sfx = format!("_{n}");
        let dot = verb.rfind('.').map(|i| i + 1).unwrap_or(0);
        let last = &verb[dot..];
        let keep = 32usize.saturating_sub(sfx.len());
        let cand = format!("{}{}{}", &verb[..dot], &last[..keep.min(last.len())], sfx);
        if !c.verbs.contains(&cand) && is_verb(&cand) {
            add_todo(c, where_, "duplicate_verb", &format!("verb '{verb}' is taken by an earlier operation; this one is '{cand}'"));
            return Ok(cand);
        }
    }
    Err(kerr("import_limit", "too many operations map to one verb"))
}

// ---- JSON pointer and the bounded schema resolver ---------------------------------------------------------------------------

/// decodeURIComponent, or the raw segment when the escape is malformed.
fn decode_uri(t: &str) -> String {
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = |x: u8| (x as char).to_digit(16);
            match (b.get(i + 1).and_then(|x| h(*x)), b.get(i + 2).and_then(|x| h(*x))) {
                (Some(hi), Some(lo)) => {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                }
                _ => return t.to_string(),
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| t.to_string())
}

/// Follow a local `#/a/b` JSON pointer in `root`; None when absent, not local, or not an object or array.
pub fn pointer<'a>(root: &'a Value, r: &Value) -> Option<&'a Value> {
    let r = r.as_str()?;
    let path = r.strip_prefix("#/")?;
    let mut cur = root;
    for raw in path.split('/') {
        let sg = decode_uri(&raw.replace("~1", "/").replace("~0", "~"));
        cur = match cur {
            Value::Object(m) => m.get(&sg)?,
            Value::Array(a) => {
                let ok = sg == "0" || (!sg.is_empty() && !sg.starts_with('0') && sg.bytes().all(|c| c.is_ascii_digit()));
                if !ok {
                    return None;
                }
                a.get(sg.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    matches!(cur, Value::Object(_) | Value::Array(_)).then_some(cur)
}

pub struct Budget {
    pub left: i64,
    pub exhausted: bool,
}
pub fn new_budget(c: &Ctx) -> Budget {
    Budget { left: c.lim.max_ref_nodes, exhausted: false }
}

fn merge_all(a: &Map<String, Value>, m: &Map<String, Value>) -> R<Map<String, Value>> {
    let mut out = a.clone();
    for (k, v) in m {
        out.insert(k.clone(), v.clone());
    }
    let mut props = spread_obj(a.get("properties"));
    for (k, v) in spread_obj(m.get("properties")) {
        props.insert(k, v);
    }
    out.insert("properties".into(), Value::Object(props));
    let nn = |v: Option<&Value>| -> Value { v.filter(|x| !x.is_null()).cloned().unwrap_or(Value::Array(vec![])) };
    let mut req = spread_arr(Some(&nn(a.get("required"))))?;
    req.extend(spread_arr(Some(&nn(m.get("required"))))?);
    out.insert("required".into(), Value::Array(req));
    Ok(out)
}

fn is_null_type(m: &Map<String, Value>) -> bool {
    match m.get("type") {
        Some(Value::String(t)) => t == "null",
        Some(Value::Array(a)) => !a.is_empty() && a.iter().all(|x| x.as_str() == Some("null")),
        _ => false,
    }
}

fn without(m: &Map<String, Value>, skip: &[&str]) -> Map<String, Value> {
    m.iter().filter(|(k, _)| !skip.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect()
}
fn overlay(mut a: Map<String, Value>, b: Map<String, Value>) -> Map<String, Value> {
    for (k, v) in b {
        a.insert(k, v);
    }
    a
}

/// Follow local `$ref`s, merge `allOf`, collapse `anyOf`/`oneOf` to the single non-null variant or to a union of string constants.
/// What stays unrepresentable is noted and left as `{}` (declared `string`, which fails closed). Bounded by `max_ref_depth` per chain
/// and one budget of nodes per operation. A non-iterable `allOf` member list is a TypeError, as in the reference.
pub fn resolve_schema(sv: &Value, c: &mut Ctx, bud: &mut Budget, where_: &str, chain: &[String], depth: i64) -> R<Map<String, Value>> {
    let Some(s0) = sv.as_object() else { return Ok(Map::new()) };
    if bud.left <= 0 {
        if !bud.exhausted {
            bud.exhausted = true;
            let n = c.lim.max_ref_nodes;
            add_todo(c, where_, "ref_budget", &format!("schema expansion stopped after {n} nodes (declared string; refine or drop)"));
        }
        return Ok(Map::new());
    }
    bud.left -= 1;
    if depth > c.lim.max_ref_depth {
        let n = c.lim.max_ref_depth;
        add_todo(c, where_, "ref_depth", &format!("schema nesting or reference chain deeper than {n} (declared string; refine or drop)"));
        return Ok(Map::new());
    }
    let mut cur: Map<String, Value> = s0.clone();
    if let Some(Value::String(r)) = s0.get("$ref") {
        let r = r.clone();
        if chain.contains(&r) {
            add_todo(c, where_, "cyclic_ref", &format!("reference '{}' is cyclic (declared string; refine or drop)", clip(&r, 120)));
            return Ok(Map::new());
        }
        let Some(target) = pointer(&c.root, &Value::String(r.clone())).cloned() else {
            add_todo(
                c,
                where_,
                "unresolved_ref",
                &format!("reference '{}' is not a local reference that resolves (declared string; refine or drop)", clip(&r, 120)),
            );
            return Ok(Map::new());
        };
        let siblings = without(s0, &["$ref"]);
        let mut ch: Vec<String> = chain.to_vec();
        ch.push(r);
        cur = overlay(resolve_schema(&target, c, bud, where_, &ch, depth + 1)?, siblings);
    }
    if let Some(Value::Array(all)) = cur.get("allOf").cloned() {
        let rest = without(&cur, &["allOf"]);
        let mut merged = Map::new();
        let mut parts = vec![];
        for m in &all {
            parts.push(resolve_schema(m, c, bud, where_, chain, depth + 1)?);
        }
        for m in &parts {
            merged = merge_all(&merged, m)?;
        }
        cur = overlay(merged, rest);
    }
    let alts: Option<Vec<Value>> = match (cur.get("anyOf"), cur.get("oneOf")) {
        (Some(Value::Array(a)), _) => Some(a.clone()),
        (_, Some(Value::Array(a))) => Some(a.clone()),
        _ => None,
    };
    if let Some(alts) = alts {
        let rest = without(&cur, &["anyOf", "oneOf"]);
        let mut live = vec![];
        for m in &alts {
            let r = resolve_schema(m, c, bud, where_, chain, depth + 1)?;
            if !is_null_type(&r) {
                live.push(r);
            }
        }
        if live.len() == 1 {
            return Ok(overlay(live.remove(0), rest));
        }
        let mut consts: Vec<Option<Vec<String>>> = vec![];
        for m in &live {
            match (m.get("const"), m.get("enum")) {
                (Some(Value::String(k)), _) => consts.push(Some(vec![k.clone()])),
                (_, Some(Value::Array(e))) if e.iter().all(Value::is_string) => {
                    consts.push(Some(e.iter().filter_map(|x| x.as_str().map(String::from)).collect()))
                }
                _ => consts.push(None),
            }
        }
        if live.len() > 1 && consts.iter().all(Option::is_some) {
            let mut out = rest;
            out.insert("type".into(), s("string"));
            let all: Vec<String> = uniq_strs(consts.into_iter().flatten().flatten());
            out.insert("enum".into(), svec(&all));
            return Ok(out);
        }
        add_todo(c, where_, "union", &format!("a union of {} schemas has no representation (declared string; refine or drop)", live.len()));
        return Ok(rest);
    }
    if !cur.contains_key("enum") {
        if let Some(Value::String(k)) = cur.get("const") {
            let k = k.clone();
            cur.insert("enum".into(), Value::Array(vec![Value::String(k)]));
        }
    }
    Ok(cur)
}
/// `resolve_schema` with an empty chain at depth 0.
pub fn resolve(sv: &Value, c: &mut Ctx, bud: &mut Budget, where_: &str) -> R<Map<String, Value>> {
    resolve_schema(sv, c, bud, where_, &[], 0)
}

// ---- JSON Schema -> params --------------------------------------------------------------------------------------------------

/// `[A-Za-z0-9_]{1,64}`; anything else is replaced by `_` (an astral character is two UTF-16 units, so two).
pub fn param_seg(raw: &str) -> String {
    let mut t: String = raw
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() || ch == '_' { ch.to_string() } else { "_".repeat(if (ch as u32) > 0xFFFF { 2 } else { 1 }) })
        .collect();
    if !t.is_empty() && t.bytes().all(|c| c == b'_') {
        t.clear();
    }
    t.truncate(64);
    if t.is_empty() {
        "p".into()
    } else {
        t
    }
}

fn format_of(f: &str) -> Option<&'static str> {
    Some(match f {
        "email" | "idn-email" => "email",
        "uuid" => "uuid",
        "uri" | "url" => "url",
        "semver" => "semver",
        _ => return None,
    })
}
const RESERVED: [&str; 3] = ["__proto__", "constructor", "prototype"];
const INT_ROLES: [&str; 4] = ["money.amount", "money.fee", "count.limit", "bytes.size"];

fn lcd(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}
fn role_ok(r: &str) -> bool {
    if CORE_ROLES.contains(&r) {
        return true;
    }
    let parts = |x: &str, min: usize, max: usize| {
        let p: Vec<&str> = x.split('.').collect();
        p.len() >= min && p.len() <= max && p.iter().all(|q| !q.is_empty() && q.bytes().all(lcd))
    };
    r.strip_prefix("id.").is_some_and(|x| parts(x, 1, 4)) || r.strip_prefix("x.").is_some_and(|x| parts(x, 2, 4))
}

fn int_num(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => is_safe_integer(v) && !(n.is_f64() && n.as_f64() == Some(0.0) && n.as_f64().is_some_and(f64::is_sign_negative)),
        _ => false,
    }
}

pub fn enum_strs(e: Option<&Value>) -> Option<Vec<String>> {
    let Some(Value::Array(a)) = e else { return None };
    let ok = !a.is_empty() && a.len() <= 256 && a.iter().all(|x| x.as_str().is_some_and(|t| !t.is_empty() && u8len(t) <= 256 && is_nfc(t)));
    ok.then(|| uniq_strs(a.iter().filter_map(|x| x.as_str().map(String::from))))
}

/// `Array.isArray(t) ? t.find(x => x !== 'null') : t` (None is undefined).
fn first_non_null(t: Option<&Value>) -> Option<Value> {
    match t {
        Some(Value::Array(a)) => a.iter().find(|x| x.as_str() != Some("null")).cloned(),
        other => other.cloned(),
    }
}

fn with_role(mut p: Map<String, Value>, role_ext: &Option<String>, c: &mut Ctx, where_: &str) -> Map<String, Value> {
    let Some(r) = role_ext else { return p };
    let ty = p.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    if !role_ok(r) || (INT_ROLES.contains(&r.as_str()) && ty != "integer") {
        add_todo(c, where_, "role_ignored", &format!("x-pca-role '{}' is not valid for a {ty} parameter", clip(r, 64)));
        return p;
    }
    p.insert("role".into(), Value::String(r.clone()));
    p
}

pub fn leaf_param(sch: &Map<String, Value>, required: bool, c: &mut Ctx, bud: &mut Budget, where_: &str) -> R<Map<String, Value>> {
    let t0 = first_non_null(sch.get("type"));
    let enum_str = enum_strs(sch.get("enum"));
    let items = sch.get("items");
    let t: Option<Value> = match &t0 {
        Some(v) if !v.is_null() => Some(v.clone()),
        _ => {
            if enum_str.is_some() {
                Some(s("string"))
            } else if matches!(items, Some(Value::Array(_)) | Some(Value::Object(_))) {
                Some(s("array"))
            } else {
                None
            }
        }
    };
    let ts: Option<&str> = t.as_ref().and_then(Value::as_str);
    let mut base = Map::new();
    base.insert("type".into(), s("string"));
    if !required {
        base.insert("required".into(), Value::Bool(false));
    }
    let desc = clipv(sch.get("description"), 280);
    if !desc.is_empty() {
        base.insert("description".into(), Value::String(desc));
    }
    let role_ext: Option<String> = if c.ext.contains("x-pca-role") { sch.get("x-pca-role").and_then(Value::as_str).map(String::from) } else { None };
    let fmt = sch.get("format");
    let fmt_s = fmt.and_then(Value::as_str);
    let with = |m: Map<String, Value>, c: &mut Ctx| with_role(m, &role_ext, c, where_);
    let set = |m: &Map<String, Value>, k: &str, v: Value| {
        let mut o = m.clone();
        o.insert(k.into(), v);
        o
    };
    if ts == Some("integer") || (ts == Some("number") && matches!(fmt_s, Some("int32") | Some("int64"))) {
        let mut p = set(&base, "type", s("integer"));
        let (mn, mx) = (sch.get("minimum"), sch.get("maximum"));
        let (ex_min, ex_max) = (sch.get("exclusiveMinimum"), sch.get("exclusiveMaximum"));
        if int_num(mn) && !is_true(ex_min) {
            p.insert("min".into(), Value::from(to_i64(mn.unwrap())));
        } else if int_num(ex_min) {
            p.insert("min".into(), Value::from(to_i64(ex_min.unwrap()) + 1));
        } else if int_num(mn) && is_true(ex_min) {
            p.insert("min".into(), Value::from(to_i64(mn.unwrap()) + 1));
        }
        if int_num(mx) && !is_true(ex_max) {
            p.insert("max".into(), Value::from(to_i64(mx.unwrap())));
        } else if int_num(ex_max) {
            p.insert("max".into(), Value::from(to_i64(ex_max.unwrap()) - 1));
        } else if int_num(mx) && is_true(ex_max) {
            p.insert("max".into(), Value::from(to_i64(mx.unwrap()) - 1));
        }
        if let (Some(a), Some(b)) = (p.get("min").and_then(Value::as_i64), p.get("max").and_then(Value::as_i64)) {
            if a > b {
                p = p.iter().filter(|(k, _)| k.as_str() != "min" && k.as_str() != "max").map(|(k, v)| (k.clone(), v.clone())).collect();
            }
        }
        return Ok(with(p, c));
    }
    if ts == Some("boolean") {
        return Ok(with(set(&base, "type", s("boolean")), c));
    }
    if ts == Some("string") {
        let f = fmt_s.unwrap_or("");
        if f == "date" {
            return Ok(with(set(&base, "type", s("date")), c));
        }
        if f == "date-time" {
            return Ok(with(set(&base, "type", s("datetime")), c));
        }
        let mut p = set(&base, "type", s("string"));
        if let Some(e) = &enum_str {
            p.insert("values".into(), svec(e));
        } else if matches!(sch.get("enum"), Some(Value::Array(a)) if !a.is_empty()) {
            add_todo(c, where_, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)");
        }
        if let Some(ff) = format_of(f) {
            p.insert("format".into(), s(ff));
        }
        let ml = sch.get("maxLength");
        if int_num(ml) && as_f(ml.unwrap()) > 0.0 && as_f(ml.unwrap()) <= 16_777_216.0 {
            p.insert("max_len".into(), Value::from(to_i64(ml.unwrap())));
        }
        return Ok(with(p, c));
    }
    if ts == Some("array") {
        let it = resolve(items.unwrap_or(&Value::Null), c, bud, &format!("{where_}[]"))?;
        let it_enum = enum_strs(it.get("enum"));
        let mut lim: Vec<(&str, i64)> = vec![];
        let (mi, mn) = (sch.get("maxItems"), sch.get("minItems"));
        if int_num(mi) && as_f(mi.unwrap()) >= 0.0 {
            lim.push(("max_items", to_i64(mi.unwrap())));
        }
        if int_num(mn) && as_f(mn.unwrap()) >= 0.0 {
            lim.push(("min_items", to_i64(mn.unwrap())));
        }
        let get_l = |k: &str, l: &Vec<(&str, i64)>| l.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
        if let (Some(a), Some(b)) = (get_l("min_items", &lim), get_l("max_items", &lim)) {
            if a > b {
                lim.clear();
            }
        }
        let add_lim = |p: &mut Map<String, Value>| {
            // key order of `{**base, ..., **lim}`: max_items then min_items when both were set in that order
            for (k, v) in &lim {
                p.insert((*k).into(), Value::from(*v));
            }
        };
        if is_true(sch.get("uniqueItems")) {
            if let Some(e) = &it_enum {
                let mut p = set(&base, "type", s("set"));
                p.insert("values".into(), svec(e));
                add_lim(&mut p);
                return Ok(with(p, c));
            }
        }
        let it_t = first_non_null(it.get("type"));
        let item: Option<String> = match &it_t {
            Some(Value::String(x)) if matches!(x.as_str(), "integer" | "string" | "boolean") => Some(x.clone()),
            _ => None,
        };
        if item.is_none() {
            if let Some(v) = &it_t {
                add_todo(c, where_, "array_items", &format!("array items of type '{}' are not declared (items left open)", clip(&js_str(v), 40)));
            }
        }
        let mut p = set(&base, "type", s("array"));
        if let Some(i) = item {
            p.insert("items".into(), Value::String(i));
        }
        add_lim(&mut p);
        return Ok(with(p, c));
    }
    let shown = match &t {
        None | Some(Value::Null) => "none".to_string(),
        Some(v) => js_str(v),
    };
    if ts == Some("number") {
        add_todo(c, where_, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)");
    } else {
        add_todo(c, where_, "unsupported_type", &format!("type '{}' has no representation (declared string; refine or drop)", clip(&shown, 40)));
    }
    Ok(with(set(&base, "type", s("string")), c))
}

/// Nested objects become dotted names up to MAX_PARAM_PATH_DEPTH segments; an object below that (or without properties) is a `string`
/// placeholder; a child of an optional parent is optional. At most MAX_DEF_PARAMS params; the rest are dropped, noted.
pub fn flatten_object(
    schema: &Map<String, Value>,
    c: &mut Ctx,
    bud: &mut Budget,
    where_: &str,
    out: &mut Map<String, Value>,
    prefix: &[String],
    parent_required: bool,
) -> R<()> {
    let empty = Map::new();
    let props = match schema.get("properties") {
        Some(Value::Object(p)) => p,
        _ => &empty,
    };
    let req: HashSet<&str> = match schema.get("required") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => HashSet::new(),
    };
    for name in sorted_keys(props) {
        if RESERVED.contains(&name.as_str()) {
            add_todo(c, &format!("{where_}: {name}"), "skipped_param", &format!("parameter name '{name}' is reserved; dropped"));
            continue;
        }
        let child = resolve(&props[&name], c, bud, &format!("{where_}: {name}"))?;
        if is_true(child.get("readOnly")) {
            continue; // response-only; not an input
        }
        let sname = param_seg(&name);
        if sname != name {
            add_todo(c, &format!("{where_}: {name}"), "renamed_param", &format!("parameter '{}' is declared as '{sname}'", clip(&name, 80)));
        }
        let mut path: Vec<String> = prefix.to_vec();
        path.push(sname);
        let full = path.join(".");
        let required = parent_required && req.contains(name.as_str());
        let is_object = child.get("type").is_some_and(|t| t.as_str() == Some("object"))
            || (!child.contains_key("type") && matches!(child.get("properties"), Some(Value::Object(_))));
        if is_object && matches!(child.get("properties"), Some(Value::Object(p)) if !p.is_empty()) && path.len() < MAX_PARAM_PATH_DEPTH {
            flatten_object(&child, c, bud, &format!("{where_}: {full}"), out, &path, required)?;
            continue;
        }
        if out.len() >= MAX_DEF_PARAMS {
            add_todo(c, where_, "too_many_params", &format!("more than {MAX_DEF_PARAMS} parameters; '{full}' and the rest are dropped"));
            return Ok(());
        }
        if out.contains_key(&full) || out.keys().any(|k| k.starts_with(&format!("{full}.")) || full.starts_with(&format!("{k}."))) {
            add_todo(c, &format!("{where_}: {full}"), "skipped_param", &format!("parameter '{full}' collides with another; kept the first"));
            continue;
        }
        let p = if is_object {
            placeholder_object(&child, required, c, &format!("{where_}: {full}"))
        } else {
            leaf_param(&child, required, c, bud, &format!("{where_}: {full}"))?
        };
        out.insert(full, Value::Object(p));
    }
    Ok(())
}

fn placeholder_object(sch: &Map<String, Value>, required: bool, c: &mut Ctx, where_: &str) -> Map<String, Value> {
    add_todo(c, where_, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)");
    let mut p = Map::new();
    p.insert("type".into(), s("string"));
    if !required {
        p.insert("required".into(), Value::Bool(false));
    }
    let d = clipv(sch.get("description"), 280);
    if !d.is_empty() {
        p.insert("description".into(), Value::String(d));
    }
    p
}

// ---- assembling a draft def -------------------------------------------------------------------------------------------------

#[derive(Default)]
pub struct EmitOpts<'a> {
    pub verb: Option<String>,
    pub title: Option<&'a Value>,
    pub description: Option<&'a Value>,
    pub idempotency: Option<Value>,
    pub traits: Option<Vec<String>>,
    pub no_alias: bool,
}

/// Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted).
pub fn emit_def(c: &mut Ctx, name: &str, effects: &[&str], scope: &str, params: Map<String, Value>, bindings: Value, o: EmitOpts) -> R<Option<Value>> {
    if c.defs.len() as i64 >= c.lim.max_ops {
        return Err(kerr("import_limit", format!("more than {} operations", c.lim.max_ops)));
    }
    let raw_verb = o.verb.clone().unwrap_or_else(|| verb_of_str(&c.ns, name));
    let pick = if is_verb(&raw_verb) { raw_verb } else { verb_of_str(&c.ns, name) };
    let verb = unique_verb(c, &pick, name)?;
    let segs: Vec<&str> = verb.split('.').collect();
    let rtype = if segs.len() > 2 { segs[..segs.len() - 1].join(".") } else { segs[0].to_string() };
    let human = Value::String(humanize(name));
    let verbv = Value::String(verb.clone());
    let ttl = first_text(MAX_TITLE_BYTES, &[o.title, Some(&human), Some(&verbv)]);
    let desc = clipv(o.description, MAX_DESCRIPTION_BYTES.min(600));
    let alias = if o.no_alias { None } else { alias_of_str(name, &verb) };
    let mut d = Map::new();
    d.insert("v".into(), Value::from(1));
    d.insert("kind".into(), s("pca-action-def"));
    d.insert("verb".into(), Value::String(verb.clone()));
    let mut alias_used: Option<String> = None;
    if let Some(a) = alias {
        if !c.aliases.contains_key(&a) && !c.verbs.contains(&a) {
            d.insert("aliases".into(), Value::Array(vec![Value::String(a.clone())]));
            alias_used = Some(a);
        }
    }
    d.insert("title".into(), Value::String(if ttl.is_empty() { verb.clone() } else { ttl }));
    if !desc.is_empty() {
        d.insert("description".into(), Value::String(desc));
    }
    let mut eff: Vec<String> = effects.iter().map(|x| x.to_string()).collect();
    eff.sort();
    eff.dedup();
    d.insert("effects".into(), svec(&eff));
    let mut res = Map::new();
    res.insert("type".into(), Value::String(if is_resource_type(&rtype) { rtype } else { segs[0].to_string() }));
    res.insert("id".into(), serde_json::json!({"prefix": "", "class": "any_safe", "len": [1, 128]}));
    res.insert("scope".into(), s(scope));
    d.insert("resource".into(), Value::Object(res));
    d.insert("params".into(), Value::Object(params));
    if let Some(i) = o.idempotency {
        if !i.is_null() {
            d.insert("idempotency".into(), i);
        }
    }
    if let Some(t) = &o.traits {
        if !t.is_empty() {
            let mut ts = t.clone();
            ts.sort();
            ts.dedup();
            d.insert("traits".into(), svec(&ts));
        }
    }
    d.insert("bindings".into(), bindings);
    d.insert("review".into(), serde_json::json!({"state": "unreviewed"}));
    let mut src = Map::new();
    for k in ["kind", "uri", "spec_digest", "licence", "imported_at"] {
        src.insert(k.into(), c.source[k].clone());
    }
    d.insert("source".into(), Value::Object(src));
    let dv = Value::Object(d);
    if let Some(bad) = validate_def(&dv) {
        add_todo(c, name, "invalid_def", &format!("not emitted: {bad}"));
        return Ok(None);
    }
    c.verbs.insert(verb.clone());
    if let Some(a) = alias_used {
        c.aliases.insert(a, verb);
    }
    c.defs.push(dv.clone());
    Ok(Some(dv))
}

pub fn with_trait(traits: Option<Vec<String>>, t: &str) -> Vec<String> {
    uniq_strs(traits.unwrap_or_default().into_iter().chain(std::iter::once(t.to_string())))
}
