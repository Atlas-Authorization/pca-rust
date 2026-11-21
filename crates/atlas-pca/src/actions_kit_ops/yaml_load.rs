//! YAML text for the authoring-file loader (`loadActionsText`). The syntax layer is the `yaml-rust2` scanner and parser (YAML 1.2);
//! only its EVENT stream is used. Everything the reference decides about meaning is done here, so the result does not depend on the
//! parser's own resolver or alias handling: the tree is built from events, plain scalars are resolved with the YAML 1.2 core schema
//! (null, bool, int, `0o` / `0x`, float, `.inf`, `.nan`; everything else a string), mapping keys are stringified the way JavaScript does,
//! aliases are refused, `<<` is an ordinary key, and positions are the 1-based start of each action and each param key.
//!
//! Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than `!!str` / `!!map` / `!!seq`, a complex
//! (non-scalar) mapping key, two keys that are equal once stringified (the reference keeps the last of `1` and `"1"`), a bare carriage
//! return used as a line break, more than one document, nesting deeper than 1000. Syntax error wording and the position of a syntax
//! error are the parser's own. shortcut: a non-finite number (`.inf`, `.nan`) has no JSON form, so as a VALUE it stays text (as a key it
//! is `Infinity` / `NaN`, as JavaScript has it); upgrade with a number type that can carry it.

use crate::intent_v2::js_number_string;
use serde_json::{Map, Number, Value};
use std::sync::LazyLock;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser, Tag};
use yaml_rust2::scanner::{Marker, TScalarStyle};

const SAFE: f64 = 9_007_199_254_740_991.0;
const MAX_DEPTH: usize = 1000;

#[derive(Debug, Clone, PartialEq)]
pub struct YamlError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

fn yerr<T>(message: impl Into<String>, line: usize, column: usize) -> Result<T, YamlError> {
    Err(YamlError { message: message.into(), line, column })
}

/// A resolved scalar.
#[derive(Debug, Clone)]
pub(crate) enum Sv {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
}

#[derive(Debug)]
pub(crate) enum Kind {
    Scalar(Sv),
    Seq(Vec<Node>),
    Map(Vec<(Node, Node)>),
}

/// A parsed node with its 1-based start position.
#[derive(Debug)]
pub(crate) struct Node {
    pub kind: Kind,
    pub line: usize,
    pub col: usize,
}

static INT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A[-+]?[0-9]+\z").expect("static"));
static OCT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A0o[0-7]+\z").expect("static"));
static HEX: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A0x[0-9a-fA-F]+\z").expect("static"));
static FLOAT: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\z").expect("static"));
static INF: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A[-+]?\.(?:inf|Inf|INF)\z").expect("static"));
static NAN: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"\A\.(?:nan|NaN|NAN)\z").expect("static"));

fn radix_f64(digits: &str, radix: u32) -> f64 {
    match u128::from_str_radix(digits, radix) {
        Ok(n) => n as f64,
        Err(_) => digits.chars().fold(0.0, |a, c| a * radix as f64 + c.to_digit(radix).unwrap_or(0) as f64),
    }
}

/// The YAML 1.2 core schema value of a plain scalar, as a JavaScript number / boolean / null / string.
pub(crate) fn resolve_core_plain(t: &str) -> Sv {
    match t {
        "" | "~" | "null" | "Null" | "NULL" => return Sv::Null,
        "true" | "True" | "TRUE" => return Sv::Bool(true),
        "false" | "False" | "FALSE" => return Sv::Bool(false),
        _ => {}
    }
    if INT.is_match(t) {
        let neg = t.starts_with('-');
        let f: f64 = t.trim_start_matches(['-', '+']).parse().unwrap_or(f64::INFINITY);
        return Sv::Num(if neg { -f } else { f });
    }
    if OCT.is_match(t) {
        return Sv::Num(radix_f64(&t[2..], 8));
    }
    if HEX.is_match(t) {
        return Sv::Num(radix_f64(&t[2..], 16));
    }
    if INF.is_match(t) {
        return Sv::Num(if t.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY });
    }
    if NAN.is_match(t) {
        return Sv::Num(f64::NAN);
    }
    if FLOAT.is_match(t) {
        if let Ok(f) = t.parse::<f64>() {
            return Sv::Num(f);
        }
    }
    Sv::Str(t.into())
}

fn js_key(v: &Sv) -> String {
    match v {
        Sv::Null => "null".into(),
        Sv::Bool(b) => b.to_string(),
        Sv::Num(f) => js_number_string(*f),
        Sv::Str(s) => s.clone(),
    }
}

fn to_json(v: &Sv) -> Value {
    match v {
        Sv::Null => Value::Null,
        Sv::Bool(b) => Value::Bool(*b),
        Sv::Str(s) => Value::String(s.clone()),
        Sv::Num(f) if !f.is_finite() => Value::String(js_number_string(*f)),
        Sv::Num(f) if f.fract() == 0.0 && f.abs() <= SAFE && !(*f == 0.0 && f.is_sign_negative()) => Value::Number(Number::from(*f as i64)),
        Sv::Num(f) => Number::from_f64(*f).map_or(Value::Null, Value::Number),
    }
}

struct Rec(Vec<(Event, Marker)>);

impl MarkedEventReceiver for Rec {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        self.0.push((ev, mark));
    }
}

fn tag_name(t: &Tag) -> String {
    format!("{}{}", t.handle, t.suffix)
}

const OK_TAGS: [&str; 3] = ["tag:yaml.org,2002:str", "tag:yaml.org,2002:map", "tag:yaml.org,2002:seq"];

struct Builder {
    events: Vec<(Event, Marker)>,
    pos: usize,
    strict: bool,
}

impl Builder {
    fn next(&mut self) -> (Event, Marker) {
        let e = self.events[self.pos].clone();
        self.pos += 1;
        e
    }

    fn peek_is(&self, f: impl Fn(&Event) -> bool) -> bool {
        self.events.get(self.pos).is_some_and(|(e, _)| f(e))
    }

    fn node(&mut self, depth: usize) -> Result<Node, YamlError> {
        if self.pos >= self.events.len() {
            return yerr("unexpected end of the parser events", 1, 1);
        }
        let (ev, mark) = self.next();
        let (line, col) = (mark.line(), mark.col() + 1);
        if depth > MAX_DEPTH {
            return yerr("the document nests too deeply", line, col);
        }
        let check_tag = |t: &Option<Tag>| match t {
            Some(t) if !OK_TAGS.contains(&tag_name(t).as_str()) => yerr(format!("Unresolved or unsupported tag: {}", tag_name(t)), line, col),
            _ => Ok(()),
        };
        match ev {
            Event::Alias(_) => yerr("Alias resolution is disabled", line, col),
            Event::Scalar(text, style, _, tag) => {
                check_tag(&tag)?;
                let v = if style == TScalarStyle::Plain && tag.is_none() { resolve_core_plain(&text) } else { Sv::Str(text) };
                Ok(Node { kind: Kind::Scalar(v), line, col })
            }
            Event::SequenceStart(_, tag) => {
                check_tag(&tag)?;
                let mut items = Vec::new();
                while !self.peek_is(|e| matches!(e, Event::SequenceEnd)) {
                    items.push(self.node(depth + 1)?);
                }
                self.pos += 1;
                Ok(Node { kind: Kind::Seq(items), line, col })
            }
            Event::MappingStart(_, tag) => {
                check_tag(&tag)?;
                let mut items: Vec<(Node, Node)> = Vec::new();
                let mut seen = std::collections::HashSet::new();
                while !self.peek_is(|e| matches!(e, Event::MappingEnd)) {
                    let key = self.node(depth + 1)?;
                    let val = self.node(depth + 1)?;
                    if self.strict {
                        let Kind::Scalar(sv) = &key.kind else { return yerr("complex mapping keys are not accepted", key.line, key.col) };
                        if !seen.insert(js_key(sv)) {
                            return yerr("Map keys must be unique", key.line, key.col);
                        }
                    }
                    items.push((key, val));
                }
                self.pos += 1;
                // a block mapping starts at its first key (the parser marks the first colon); a flow mapping at its `{`, before the key
                let (line, col) = match items.first() {
                    Some((k, _)) if k.line == line && k.col < col => (k.line, k.col),
                    _ => (line, col),
                };
                Ok(Node { kind: Kind::Map(items), line, col })
            }
            other => yerr(format!("unexpected parser event {other:?}"), line, col),
        }
    }
}

/// The one document of `text` as a node tree (`None` for an empty stream). `strict` (YAML files) refuses complex and duplicate keys;
/// JSON text is parsed leniently because only its positions are used.
pub(crate) fn parse_document(text: &str, strict: bool) -> Result<Option<Node>, YamlError> {
    if text.replace("\r\n", "").contains('\r') {
        return yerr("bare carriage return is not accepted as a line break", 1, 1);
    }
    let mut rec = Rec(Vec::new());
    if let Err(e) = Parser::new_from_str(text).load(&mut rec, true) {
        let m = e.marker();
        return yerr(e.info().to_string(), m.line(), m.col() + 1);
    }
    let mut b = Builder { events: rec.0, pos: 0, strict };
    let mut docs = 0;
    let mut root = None;
    while b.pos < b.events.len() {
        if matches!(b.events[b.pos].0, Event::DocumentStart) {
            docs += 1;
            if docs > 1 {
                return yerr("Source contains multiple documents; please use YAML.parseAllDocuments()", 1, 1);
            }
            b.pos += 1;
            if !b.peek_is(|e| matches!(e, Event::DocumentEnd)) {
                root = Some(b.node(0)?);
            }
        } else {
            b.pos += 1;
        }
    }
    Ok(root)
}

pub(crate) fn to_value(n: &Option<Node>) -> Result<Value, YamlError> {
    fn go(n: &Node) -> Result<Value, YamlError> {
        match &n.kind {
            Kind::Scalar(s) => Ok(to_json(s)),
            Kind::Seq(items) => Ok(Value::Array(items.iter().map(go).collect::<Result<_, _>>()?)),
            Kind::Map(items) => {
                let mut o = Map::new();
                for (k, v) in items {
                    let Kind::Scalar(sv) = &k.kind else { return yerr("complex mapping keys are not accepted", k.line, k.col) };
                    o.insert(js_key(sv), go(v)?);
                }
                Ok(Value::Object(o))
            }
        }
    }
    n.as_ref().map_or(Ok(Value::Null), go)
}

/// One authoring entry's position and the positions of the keys of its params.
pub(crate) struct Pos {
    item: (usize, usize),
    params: Vec<(String, (usize, usize))>,
}

fn scalar_key<'a>(k: &'a Node, name: &str) -> bool {
    matches!(&k.kind, Kind::Scalar(Sv::Str(s)) if s == name)
}

/// Per-entry positions of an authoring document (`actions` items and their `params` keys); `None` when it is not a mapping.
pub(crate) fn positions_of(root: &Option<Node>) -> Option<Vec<Pos>> {
    let root = root.as_ref()?;
    let Kind::Map(rm) = &root.kind else { return None };
    let actions = rm.iter().rev().find(|(k, _)| scalar_key(k, "actions")).map(|(_, v)| v);
    let items: Vec<&Node> = match actions {
        Some(Node { kind: Kind::Seq(xs), .. }) => xs.iter().collect(),
        _ => vec![root],
    };
    Some(
        items
            .into_iter()
            .map(|it| {
                let mut params = Vec::new();
                if let Kind::Map(im) = &it.kind {
                    if let Some((_, Node { kind: Kind::Map(pm), .. })) = im.iter().rev().find(|(k, _)| scalar_key(k, "params")) {
                        for (k, _) in pm {
                            if let Kind::Scalar(sv) = &k.kind {
                                let name = if matches!(sv, Sv::Null) { String::new() } else { js_key(sv) };
                                params.push((name, (k.line, k.col)));
                            }
                        }
                    }
                }
                Pos { item: (it.line, it.col), params }
            })
            .collect(),
    )
}

fn lc(line: usize, col: usize) -> Value {
    serde_json::json!({"line": line, "column": col})
}

pub(crate) fn attach_positions(res: &mut Value, pos: &[Pos]) {
    let errors: Vec<Value> = res["errors"].as_array().cloned().unwrap_or_default();
    let failed: Vec<usize> = errors.iter().filter_map(|e| e.get("index").and_then(Value::as_u64)).map(|i| i as usize).collect();
    let order: Vec<usize> = (0..pos.len()).filter(|i| !failed.contains(i)).collect();
    let defs: Vec<Value> = res["defs"].as_array().cloned().unwrap_or_default();
    for (k, d) in defs.iter().enumerate() {
        let Some(p) = order.get(k).and_then(|i| pos.get(*i)) else { continue };
        let mut o = Map::new();
        o.insert("line".into(), p.item.0.into());
        o.insert("column".into(), p.item.1.into());
        let mut params = Map::new();
        for (name, (l, c)) in &p.params {
            params.insert(name.clone(), lc(*l, *c));
        }
        o.insert("params".into(), Value::Object(params));
        if let (Some(verb), Some(locs)) = (d["verb"].as_str(), res["locs"].as_object_mut()) {
            locs.insert(verb.to_string(), Value::Object(o));
        }
    }
    if let Some(errs) = res["errors"].as_array_mut() {
        for e in errs {
            let idx = e.get("index").and_then(Value::as_u64).map(|i| i as usize);
            let at = match idx {
                Some(i) => pos.get(i).map(|p| p.item),
                None => Some((1, 1)),
            };
            if let (Some((l, c)), Some(o)) = (at, e.as_object_mut()) {
                o.insert("line".into(), l.into());
                o.insert("column".into(), c.into());
            }
        }
    }
}

fn fail(message: String, line: usize, column: usize) -> Value {
    serde_json::json!({"defs": [], "notes": [], "errors": [{"message": message, "line": line, "column": column}], "locs": {}, "rules": {}})
}

/// Load an authoring file (YAML 1.2 core or JSON, `fmt` is "yaml" or "json") with source positions. Input above
/// [`MAX_AUTHOR_BYTES`](crate::actions_kit::author::MAX_AUTHOR_BYTES) is refused. Never errs: a failure is the `errors` list of the result.
pub fn load_actions_text(text: &str, fmt: &str) -> Value {
    use crate::actions_kit::author::{load_actions_value_with, MAX_AUTHOR_BYTES};
    if text.len() > MAX_AUTHOR_BYTES {
        return fail(format!("the file is larger than {MAX_AUTHOR_BYTES} bytes"), 1, 1);
    }
    let rules_check = |d: &Value, r: &Value| super::rules::business_rules_error(d, r);
    let (value, positions) = if fmt == "json" {
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => return fail(format!("not JSON: {e}"), 1, 1),
        };
        // JSON is YAML: only the positions come from the YAML parse, the value from the JSON parse
        let positions = parse_document(text, false).ok().and_then(|r| positions_of(&r));
        (value, positions)
    } else {
        match parse_document(text, true).and_then(|root| Ok((to_value(&root)?, positions_of(&root)))) {
            Ok(x) => x,
            Err(e) => return fail(format!("not YAML: {}", e.message), e.line, e.column),
        }
    };
    let mut res = load_actions_value_with(&value, &rules_check);
    if let Some(p) = positions {
        attach_positions(&mut res, &p);
    }
    res
}

/// One YAML document as a JSON value (`null` for an empty stream); errors carry the 1-based line.
pub fn parse(text: &str) -> Result<Value, String> {
    let root = parse_document(text, true).map_err(|e| format!("{} (line {})", e.message, e.line))?;
    to_value(&root).map_err(|e| format!("{} (line {})", e.message, e.line))
}
