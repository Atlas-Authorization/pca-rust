//! Protobuf services to drafts, from `.proto` text or a binary FileDescriptorSet (native port of the gRPC importer of the reference
//! action-kit package). `service.method` becomes the verb; `google.api.http` gives method and path; `idempotency_level` gives read /
//! idempotent; field behavior (REQUIRED, OUTPUT_ONLY) refines params; streaming methods get `pca.bulk`. Offline, bounded, no code
//! generation. A [`ProtoModel`] renders as `{messages: [[full, {full, fields, mapEntry}]...], enums: [[full, values]...], services}`.

use super::common::{
    add_todo, clip, emit_def, finish, flatten_object, kerr, new_budget, new_ctx, s, svec, uniq_strs, with_trait, ActionKitError, Ctx, EmitOpts, Source, R,
};
use crate::action_schema::is_js_ws;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::LazyLock;

static CAMEL: LazyLock<Regex> = LazyLock::new(|| Regex::new("([a-z0-9])([A-Z])").expect("static regex"));

fn bad(msg: impl Into<String>) -> ActionKitError {
    kerr("bad_source", msg)
}

const SCALAR_NAMES: [&str; 15] =
    ["double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes"];

// ---- model ------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ProtoField {
    pub name: String,
    pub typ: String,
    pub scope: String,
    pub repeated: bool,
    pub optional: bool,
    pub behavior: Vec<String>,
    pub map: Option<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct ProtoMessage {
    pub full: String,
    pub fields: Vec<ProtoField>,
    pub map_entry: bool,
}

#[derive(Clone, Debug)]
pub struct ProtoEnum {
    pub full: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProtoHttp {
    pub method: String,
    pub path: String,
    pub body: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ProtoMethod {
    pub name: String,
    pub input: String,
    pub output: String,
    pub cs: bool,
    pub ss: bool,
    pub scope: String,
    pub idem: Option<String>,
    pub http: Option<ProtoHttp>,
}

#[derive(Clone, Debug)]
pub struct ProtoService {
    pub full: String,
    pub name: String,
    pub methods: Vec<ProtoMethod>,
}

#[derive(Clone, Debug, Default)]
pub struct ProtoModel {
    pub messages: Vec<ProtoMessage>,
    pub enums: Vec<ProtoEnum>,
    pub services: Vec<ProtoService>,
    msg_idx: HashMap<String, usize>,
    enum_idx: HashMap<String, usize>,
}

impl ProtoModel {
    pub fn message(&self, full: &str) -> Option<&ProtoMessage> {
        self.msg_idx.get(full).map(|&i| &self.messages[i])
    }

    pub fn enum_(&self, full: &str) -> Option<&ProtoEnum> {
        self.enum_idx.get(full).map(|&i| &self.enums[i])
    }

    /// `messages[full] = msg`: a repeated name keeps its first position.
    fn put_message(&mut self, msg: ProtoMessage) {
        match self.msg_idx.get(&msg.full) {
            Some(&i) => self.messages[i] = msg,
            None => {
                self.msg_idx.insert(msg.full.clone(), self.messages.len());
                self.messages.push(msg);
            }
        }
    }

    fn put_enum(&mut self, e: ProtoEnum) {
        match self.enum_idx.get(&e.full) {
            Some(&i) => self.enums[i] = e,
            None => {
                self.enum_idx.insert(e.full.clone(), self.enums.len());
                self.enums.push(e);
            }
        }
    }

    pub fn to_json(&self) -> Value {
        let messages: Vec<Value> = self
            .messages
            .iter()
            .map(|m| {
                let fields: Vec<Value> = m
                    .fields
                    .iter()
                    .map(|f| {
                        let mut o = Map::new();
                        o.insert("name".into(), s(&f.name));
                        o.insert("type".into(), s(&f.typ));
                        o.insert("scope".into(), s(&f.scope));
                        o.insert("repeated".into(), Value::Bool(f.repeated));
                        o.insert("optional".into(), Value::Bool(f.optional));
                        o.insert("behavior".into(), svec(&f.behavior));
                        if let Some((k, v)) = &f.map {
                            o.insert("map".into(), json!([k, v]));
                        }
                        Value::Object(o)
                    })
                    .collect();
                json!([m.full, {"full": m.full, "fields": fields, "mapEntry": m.map_entry}])
            })
            .collect();
        let enums: Vec<Value> = self.enums.iter().map(|e| json!([e.full, svec(&e.values)])).collect();
        let services: Vec<Value> = self
            .services
            .iter()
            .map(|sv| {
                let methods: Vec<Value> = sv
                    .methods
                    .iter()
                    .map(|m| {
                        let mut o = Map::new();
                        o.insert("name".into(), s(&m.name));
                        o.insert("input".into(), s(&m.input));
                        o.insert("output".into(), s(&m.output));
                        o.insert("cs".into(), Value::Bool(m.cs));
                        o.insert("ss".into(), Value::Bool(m.ss));
                        o.insert("scope".into(), s(&m.scope));
                        if let Some(i) = &m.idem {
                            o.insert("idem".into(), s(i));
                        }
                        if let Some(h) = &m.http {
                            let mut ho = Map::new();
                            ho.insert("method".into(), s(&h.method));
                            ho.insert("path".into(), s(&h.path));
                            if let Some(b) = &h.body {
                                ho.insert("body".into(), s(b));
                            }
                            o.insert("http".into(), Value::Object(ho));
                        }
                        Value::Object(o)
                    })
                    .collect();
                json!({"full": sv.full, "name": sv.name, "methods": methods})
            })
            .collect();
        json!({"messages": messages, "enums": enums, "services": services})
    }
}

fn qual(scope: &str, name: &str) -> String {
    if scope.is_empty() {
        name.to_string()
    } else {
        format!("{scope}.{name}")
    }
}

// ---- .proto text lexer ------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    Str,
    Id,
    Num,
    P,
}

#[derive(Clone)]
struct Tok {
    k: K,
    v: String,
}

fn starts(c: &[char], i: usize, p: &str) -> bool {
    let mut k = i;
    for ch in p.chars() {
        if c.get(k) != Some(&ch) {
            return false;
        }
        k += 1;
    }
    true
}

fn push(out: &mut Vec<Tok>, max: usize, k: K, v: String) -> R<()> {
    if out.len() >= max {
        return Err(kerr("import_limit", "the proto source has too many tokens"));
    }
    out.push(Tok { k, v });
    Ok(())
}

fn lex(src: &str, max_tokens: usize) -> R<Vec<Tok>> {
    let c: Vec<char> = src.chars().collect();
    let n = c.len();
    let mut out: Vec<Tok> = vec![];
    let mut i = 0usize;
    while i < n {
        let ch = c[i];
        if is_js_ws(ch) {
            i += 1;
            continue;
        }
        if starts(&c, i, "//") {
            while i < n && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if starts(&c, i, "/*") {
            let mut j = i + 2;
            loop {
                if j >= n {
                    return Err(bad("unterminated comment in proto source"));
                }
                if starts(&c, j, "*/") {
                    break;
                }
                j += 1;
            }
            i = j + 2;
            continue;
        }
        if ch == '"' || ch == '\'' {
            let mut j = i + 1;
            let mut t = String::new();
            while j < n && c[j] != ch {
                if c[j] == '\n' {
                    return Err(bad("unterminated string in proto source"));
                }
                if c[j] == '\\' {
                    if j + 1 < n {
                        t.push(c[j + 1]);
                    }
                    j += 2;
                } else {
                    t.push(c[j]);
                    j += 1;
                }
            }
            if j >= n {
                return Err(bad("unterminated string in proto source"));
            }
            push(&mut out, max_tokens, K::Str, t)?;
            i = j + 1;
            continue;
        }
        if ch == '_' || ch == '.' || ch.is_ascii_alphabetic() {
            let mut j = i + 1;
            while j < n && (c[j] == '_' || c[j] == '.' || c[j].is_ascii_alphanumeric()) {
                j += 1;
            }
            push(&mut out, max_tokens, K::Id, c[i..j].iter().collect())?;
            i = j;
            continue;
        }
        if ch == '-' || ch.is_ascii_digit() {
            let mut j = i + 1;
            while j < n && (matches!(c[j], '-' | '+' | '.') || c[j].is_ascii_alphanumeric()) {
                j += 1;
            }
            push(&mut out, max_tokens, K::Num, c[i..j].iter().collect())?;
            i = j;
            continue;
        }
        if "{}[]()<>=;,:".contains(ch) {
            push(&mut out, max_tokens, K::P, ch.to_string())?;
            i += 1;
            continue;
        }
        return Err(bad(format!("unexpected character in proto source at offset {i}")));
    }
    Ok(out)
}

// ---- .proto text parser -----------------------------------------------------------------------------------------------------

struct PP {
    i: usize,
    pkg: String,
    toks: Vec<Tok>,
    m: ProtoModel,
    max_depth: usize,
}

impl PP {
    fn cur(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }

    fn is_(&self, v: &str) -> bool {
        matches!(self.cur(), Some(t) if t.k != K::Str && t.v == v)
    }

    fn eat(&mut self, v: &str) -> bool {
        if self.is_(v) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn fail<T>(&self, msg: &str) -> R<T> {
        let near = match self.cur() {
            Some(t) => clip(&t.v, 30),
            None => clip("<end>", 30),
        };
        Err(bad(format!("proto parse error: {msg} near '{near}'")))
    }

    fn expect(&mut self, v: &str) -> R<()> {
        if self.eat(v) {
            Ok(())
        } else {
            self.fail(&format!("expected '{v}'"))
        }
    }

    fn id(&mut self) -> R<String> {
        match self.cur() {
            Some(t) if t.k == K::Id => {
                let v = t.v.clone();
                self.i += 1;
                Ok(v)
            }
            _ => self.fail("expected an identifier"),
        }
    }

    fn take(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.i).cloned();
        self.i += 1;
        t
    }

    fn skip_to(&mut self, open: &str, close: &str) -> R<()> {
        let mut depth = 1usize;
        while depth > 0 {
            let Some(t) = self.take() else {
                self.i = self.toks.len();
                return self.fail("unterminated block");
            };
            if t.k == K::P {
                if t.v == open {
                    depth += 1;
                } else if t.v == close {
                    depth -= 1;
                }
            }
        }
        Ok(())
    }

    fn skip_statement(&mut self) -> R<()> {
        while self.cur().is_some() && !self.is_(";") {
            if self.is_("{") {
                self.i += 1;
                return self.skip_to("{", "}");
            }
            self.i += 1;
        }
        self.eat(";");
        Ok(())
    }

    fn file(&mut self) -> R<()> {
        while self.cur().is_some() {
            if self.eat(";") {
                continue;
            }
            let kw = self.id()?;
            match kw.as_str() {
                "package" => {
                    self.pkg = self.id()?;
                    self.expect(";")?;
                }
                "message" => {
                    let pkg = self.pkg.clone();
                    self.message(&pkg, 0)?;
                }
                "enum" => {
                    let pkg = self.pkg.clone();
                    self.enum_def(&pkg)?;
                }
                "service" => self.service()?,
                "extend" => {
                    self.id()?;
                    self.expect("{")?;
                    self.skip_to("{", "}")?;
                }
                _ => self.skip_statement()?,
            }
        }
        Ok(())
    }

    fn enum_def(&mut self, scope: &str) -> R<()> {
        let n = self.id()?;
        let full = qual(scope, &n);
        self.expect("{")?;
        let mut values: Vec<String> = vec![];
        while !self.is_("}") {
            if self.cur().is_none() {
                return self.fail("unterminated enum");
            }
            if self.is_("option") || self.is_("reserved") {
                self.skip_statement()?;
                continue;
            }
            values.push(self.id()?);
            self.skip_statement()?;
        }
        self.expect("}")?;
        self.m.put_enum(ProtoEnum { full, values });
        Ok(())
    }

    fn field_options(&mut self) -> R<Vec<String>> {
        let mut behavior: Vec<String> = vec![];
        if !self.eat("[") {
            return Ok(behavior);
        }
        let mut depth = 1usize;
        let mut in_behavior = false;
        while depth > 0 {
            let Some(t) = self.take() else {
                self.i = self.toks.len();
                return self.fail("unterminated field options");
            };
            if t.k == K::P {
                match t.v.as_str() {
                    "[" | "{" => depth += 1,
                    "]" | "}" => depth -= 1,
                    "," => in_behavior = false,
                    _ => {}
                }
            } else if t.k == K::Id {
                if t.v.ends_with("field_behavior") {
                    in_behavior = true;
                } else if in_behavior && !t.v.is_empty() && t.v.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_') {
                    behavior.push(t.v);
                }
            }
        }
        Ok(behavior)
    }

    fn field(&mut self, full: &str, label: Option<&str>, oneof: bool) -> R<ProtoField> {
        let mut repeated = label == Some("repeated");
        let mut typ = self.id()?;
        let mut fmap: Option<(String, String)> = None;
        if typ == "map" && self.eat("<") {
            let k = self.id()?;
            self.expect(",")?;
            let v = self.id()?;
            self.expect(">")?;
            fmap = Some((k, v));
            typ = "map".to_string();
            repeated = false;
        }
        let fname = self.id()?;
        self.expect("=")?;
        self.i += 1; // field number
        let behavior = self.field_options()?;
        self.expect(";")?;
        Ok(ProtoField { name: fname, typ, scope: full.to_string(), repeated, optional: label == Some("optional") || oneof, behavior, map: fmap })
    }

    fn message(&mut self, scope: &str, depth: usize) -> R<()> {
        if depth > self.max_depth {
            return Err(kerr("import_limit", "proto message nesting is too deep"));
        }
        let n = self.id()?;
        let full = qual(scope, &n);
        self.m.put_message(ProtoMessage { full: full.clone(), fields: vec![], map_entry: false });
        self.expect("{")?;
        let mut fields: Vec<ProtoField> = vec![];
        while !self.is_("}") {
            if self.cur().is_none() {
                return self.fail("unterminated message");
            }
            if self.eat(";") {
                continue;
            }
            let kw = match self.cur() {
                Some(t) if t.k == K::Id => t.v.clone(),
                _ => String::new(),
            };
            match kw.as_str() {
                "message" => {
                    self.i += 1;
                    self.message(&full, depth + 1)?;
                }
                "enum" => {
                    self.i += 1;
                    self.enum_def(&full)?;
                }
                "oneof" => {
                    self.i += 1;
                    self.id()?;
                    self.expect("{")?;
                    while !self.is_("}") {
                        if self.cur().is_none() {
                            return self.fail("unterminated oneof");
                        }
                        if self.is_("option") {
                            self.skip_statement()?;
                            continue;
                        }
                        let f = self.field(&full, None, true)?;
                        fields.push(f);
                    }
                    self.expect("}")?;
                }
                "option" | "reserved" | "extensions" | "group" => self.skip_statement()?,
                "extend" => {
                    self.i += 1;
                    self.id()?;
                    self.expect("{")?;
                    self.skip_to("{", "}")?;
                }
                "repeated" | "optional" | "required" => {
                    self.i += 1;
                    let f = self.field(&full, Some(kw.as_str()), false)?;
                    fields.push(f);
                }
                _ => {
                    let f = self.field(&full, None, false)?;
                    fields.push(f);
                }
            }
        }
        self.expect("}")?;
        if let Some(&ix) = self.m.msg_idx.get(&full) {
            self.m.messages[ix].fields = fields;
        }
        Ok(())
    }

    fn stream(&mut self) -> bool {
        match self.cur() {
            Some(t) if t.v == "stream" && t.k == K::Id => {
                self.i += 1;
                true
            }
            _ => false,
        }
    }

    fn service(&mut self) -> R<()> {
        let name = self.id()?;
        let mut svc = ProtoService { full: qual(&self.pkg, &name), name, methods: vec![] };
        self.expect("{")?;
        while !self.is_("}") {
            if self.cur().is_none() {
                return self.fail("unterminated service");
            }
            if self.eat(";") {
                continue;
            }
            if self.id()? != "rpc" {
                self.skip_statement()?;
                continue;
            }
            let mname = self.id()?;
            self.expect("(")?;
            let cs = self.stream();
            let inp = self.id()?;
            self.expect(")")?;
            if self.id()? != "returns" {
                return self.fail("expected 'returns'");
            }
            self.expect("(")?;
            let ss = self.stream();
            let out = self.id()?;
            self.expect(")")?;
            let mut m = ProtoMethod { name: mname, input: inp, output: out, cs, ss, scope: self.pkg.clone(), idem: None, http: None };
            if self.eat("{") {
                while !self.is_("}") {
                    if self.cur().is_none() {
                        return self.fail("unterminated rpc body");
                    }
                    if !self.is_("option") {
                        self.skip_statement()?;
                        continue;
                    }
                    self.i += 1;
                    let oname;
                    if self.eat("(") {
                        oname = self.id()?;
                        self.expect(")")?;
                    } else {
                        oname = self.id()?;
                    }
                    self.expect("=")?;
                    if self.is_("{") {
                        self.i += 1;
                        let mut depth = 1usize;
                        while depth > 0 {
                            let Some(t) = self.take() else {
                                self.i = self.toks.len();
                                return self.fail("unterminated option");
                            };
                            if t.k == K::P {
                                if t.v == "{" {
                                    depth += 1;
                                } else if t.v == "}" {
                                    depth -= 1;
                                }
                                continue;
                            }
                            let http_opt = depth == 1 && oname.ends_with("http") && t.k == K::Id;
                            if http_opt && matches!(t.v.as_str(), "get" | "put" | "post" | "delete" | "patch") && self.is_(":") {
                                self.i += 1;
                                let path = match self.cur() {
                                    Some(p) if p.k == K::Str => p.v.clone(),
                                    _ => String::new(),
                                };
                                self.i += 1;
                                if m.http.is_none() {
                                    m.http = Some(ProtoHttp { method: t.v.to_uppercase(), path, body: None });
                                }
                            } else if http_opt && t.v == "body" && self.is_(":") {
                                self.i += 1;
                                let body = match self.cur() {
                                    Some(p) if p.k == K::Str => Some(p.v.clone()),
                                    _ => None,
                                };
                                if let (Some(b), Some(h)) = (body, m.http.as_mut()) {
                                    h.body = Some(b);
                                }
                                self.i += 1;
                            }
                        }
                        self.eat(";");
                    } else {
                        let v = self.cur().map(|t| t.v.clone());
                        self.i += 1;
                        if oname.ends_with("idempotency_level") {
                            if let Some(v) = v {
                                m.idem = Some(v);
                            }
                        }
                        self.eat(";");
                    }
                }
                self.expect("}")?;
                self.eat(";");
            } else {
                self.expect(";")?;
            }
            svc.methods.push(m);
        }
        self.expect("}")?;
        self.m.services.push(svc);
        Ok(())
    }
}

pub fn parse_proto(src: &str) -> R<ProtoModel> {
    let toks = lex(src, 2_000_000)?;
    let mut p = PP { i: 0, pkg: String::new(), toks, m: ProtoModel::default(), max_depth: 32 };
    p.file()?;
    Ok(p.m)
}

// ---- binary descriptor set --------------------------------------------------------------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0, end: b.len() }
    }

    fn more(&self) -> bool {
        self.p < self.end
    }

    /// A JavaScript number: accumulated in double arithmetic, as the reference does (a 10-byte varint loses low bits).
    fn varint(&mut self) -> R<f64> {
        let mut r = 0.0f64;
        let mut mul = 1.0f64;
        for _ in 0..10 {
            if self.p >= self.end {
                return Err(bad("truncated descriptor"));
            }
            let byte = self.b[self.p];
            self.p += 1;
            r += f64::from(byte & 0x7f) * mul;
            if byte & 0x80 == 0 {
                return Ok(r);
            }
            mul *= 128.0;
        }
        Err(bad("overlong varint in descriptor"))
    }

    fn len(&mut self) -> R<Reader<'a>> {
        let n = self.varint()?;
        if n > (self.end - self.p) as f64 {
            return Err(bad("descriptor length exceeds the buffer"));
        }
        let k = n as usize;
        let r = Reader { b: self.b, p: self.p, end: self.p + k };
        self.p += k;
        Ok(r)
    }

    fn adv(&mut self, n: usize) -> R<()> {
        if n > self.end - self.p {
            return Err(bad("truncated descriptor"));
        }
        self.p += n;
        Ok(())
    }

    fn skip(&mut self, wt: u32) -> R<()> {
        match wt {
            0 => {
                self.varint()?;
                Ok(())
            }
            1 => self.adv(8),
            2 => {
                self.len()?;
                Ok(())
            }
            5 => self.adv(4),
            _ => Err(bad(format!("unsupported wire type {wt} in descriptor"))),
        }
    }

    fn str_(&mut self) -> R<String> {
        let r = self.len()?;
        let mut raw = &r.b[r.p..r.end];
        if raw.starts_with(&[0xef, 0xbb, 0xbf]) {
            raw = &raw[3..]; // TextDecoder drops a leading byte-order mark
        }
        Ok(String::from_utf8_lossy(raw).into_owned())
    }
}

/// (field number, wire type) of a tag, as the reference computes them from a double.
fn tag(r: &mut Reader) -> R<(f64, u32)> {
    let t = r.varint()?;
    Ok(((t / 8.0).floor(), (t % 8.0) as u32))
}

fn ftype(t: f64) -> &'static str {
    if !(t.is_finite() && t.fract() == 0.0 && (0.0..100.0).contains(&t)) {
        return "bytes";
    }
    match t as u32 {
        1 => "double",
        2 => "float",
        3 => "int64",
        4 => "uint64",
        5 => "int32",
        6 => "fixed64",
        7 => "fixed32",
        8 => "bool",
        9 => "string",
        12 => "bytes",
        13 => "uint32",
        15 => "sfixed32",
        16 => "sfixed64",
        17 => "sint32",
        18 => "sint64",
        _ => "bytes",
    }
}

fn behavior_name(b: f64) -> &'static str {
    if b == 2.0 {
        "REQUIRED"
    } else if b == 3.0 {
        "OUTPUT_ONLY"
    } else if b == 4.0 {
        "INPUT_ONLY"
    } else if b == 5.0 {
        "IMMUTABLE"
    } else {
        ""
    }
}

fn read_enum(m: &mut ProtoModel, mut r: Reader, scope: &str) -> R<()> {
    let mut name = String::new();
    let mut values: Vec<String> = vec![];
    while r.more() {
        let (f, wt) = tag(&mut r)?;
        if f == 1.0 && wt == 2 {
            name = r.str_()?;
        } else if f == 2.0 && wt == 2 {
            let mut v = r.len()?;
            while v.more() {
                let (vf, vw) = tag(&mut v)?;
                if vf == 1.0 && vw == 2 {
                    values.push(v.str_()?);
                } else {
                    v.skip(vw)?;
                }
            }
        } else {
            r.skip(wt)?;
        }
    }
    let full = qual(scope, &name);
    m.put_enum(ProtoEnum { full, values });
    Ok(())
}

struct FieldDesc {
    name: String,
    typ: f64,
    label: f64,
    type_name: String,
    proto3opt: bool,
    behavior: Vec<f64>,
}

fn read_msg(m: &mut ProtoModel, mut r: Reader, scope: &str, depth: usize) -> R<()> {
    if depth > 32 {
        return Err(kerr("import_limit", "descriptor message nesting is too deep"));
    }
    let mut name = String::new();
    let mut fields: Vec<FieldDesc> = vec![];
    let mut nested: Vec<Reader> = vec![];
    let mut enums: Vec<Reader> = vec![];
    let mut map_entry = false;
    while r.more() {
        let (f, wt) = tag(&mut r)?;
        if f == 1.0 && wt == 2 {
            name = r.str_()?;
        } else if f == 2.0 && wt == 2 {
            let mut fr = r.len()?;
            let mut fd = FieldDesc { name: String::new(), typ: 0.0, label: 1.0, type_name: String::new(), proto3opt: false, behavior: vec![] };
            while fr.more() {
                let (ff, fw) = tag(&mut fr)?;
                if ff == 1.0 && fw == 2 {
                    fd.name = fr.str_()?;
                } else if ff == 4.0 && fw == 0 {
                    fd.label = fr.varint()?;
                } else if ff == 5.0 && fw == 0 {
                    fd.typ = fr.varint()?;
                } else if ff == 6.0 && fw == 2 {
                    fd.type_name = fr.str_()?;
                } else if ff == 17.0 && fw == 0 {
                    fd.proto3opt = fr.varint()? == 1.0;
                } else if ff == 8.0 && fw == 2 {
                    let mut o = fr.len()?;
                    while o.more() {
                        let (of, ow) = tag(&mut o)?;
                        if of == 1052.0 && ow == 0 {
                            fd.behavior.push(o.varint()?);
                        } else if of == 1052.0 && ow == 2 {
                            let mut pk = o.len()?;
                            while pk.more() {
                                fd.behavior.push(pk.varint()?);
                            }
                        } else {
                            o.skip(ow)?;
                        }
                    }
                } else {
                    fr.skip(fw)?;
                }
            }
            fields.push(fd);
        } else if f == 3.0 && wt == 2 {
            nested.push(r.len()?);
        } else if f == 4.0 && wt == 2 {
            enums.push(r.len()?);
        } else if f == 7.0 && wt == 2 {
            let mut o = r.len()?;
            while o.more() {
                let (of, ow) = tag(&mut o)?;
                if of == 7.0 && ow == 0 {
                    map_entry = o.varint()? == 1.0;
                } else {
                    o.skip(ow)?;
                }
            }
        } else {
            r.skip(wt)?;
        }
    }
    let full = qual(scope, &name);
    let fs: Vec<ProtoField> = fields
        .iter()
        .map(|f| ProtoField {
            name: f.name.clone(),
            typ: if f.type_name.is_empty() { ftype(f.typ).to_string() } else { f.type_name.clone() },
            scope: full.clone(),
            repeated: f.label == 3.0,
            optional: f.proto3opt,
            behavior: f.behavior.iter().map(|b| behavior_name(*b).to_string()).collect(),
            map: None,
        })
        .collect();
    m.put_message(ProtoMessage { full: full.clone(), fields: fs, map_entry });
    for n in nested {
        read_msg(m, n, &full, depth + 1)?;
    }
    for e in enums {
        read_enum(m, e, &full)?;
    }
    Ok(())
}

fn read_method(mut mr: Reader, pkg: &str) -> R<ProtoMethod> {
    let mut me =
        ProtoMethod { name: String::new(), input: String::new(), output: String::new(), cs: false, ss: false, scope: pkg.to_string(), idem: None, http: None };
    while mr.more() {
        let (mf, mw) = tag(&mut mr)?;
        if mf == 1.0 && mw == 2 {
            me.name = mr.str_()?;
        } else if mf == 2.0 && mw == 2 {
            me.input = mr.str_()?;
        } else if mf == 3.0 && mw == 2 {
            me.output = mr.str_()?;
        } else if mf == 5.0 && mw == 0 {
            me.cs = mr.varint()? == 1.0;
        } else if mf == 6.0 && mw == 0 {
            me.ss = mr.varint()? == 1.0;
        } else if mf == 4.0 && mw == 2 {
            let mut o = mr.len()?;
            while o.more() {
                let (of, ow) = tag(&mut o)?;
                if of == 34.0 && ow == 0 {
                    let v = o.varint()?;
                    let level = if v == 1.0 {
                        "NO_SIDE_EFFECTS"
                    } else if v == 2.0 {
                        "IDEMPOTENT"
                    } else {
                        "IDEMPOTENCY_UNKNOWN"
                    };
                    me.idem = Some(level.to_string());
                } else if of == 72295728.0 && ow == 2 {
                    let mut h = o.len()?;
                    while h.more() {
                        let (hf, hw) = tag(&mut h)?;
                        let verb = if hw == 2 {
                            match hf as i64 {
                                2 if hf == 2.0 => Some("GET"),
                                3 if hf == 3.0 => Some("PUT"),
                                4 if hf == 4.0 => Some("POST"),
                                5 if hf == 5.0 => Some("DELETE"),
                                6 if hf == 6.0 => Some("PATCH"),
                                _ => None,
                            }
                        } else {
                            None
                        };
                        if let Some(v) = verb {
                            let path = h.str_()?;
                            if me.http.is_none() {
                                me.http = Some(ProtoHttp { method: v.to_string(), path, body: None });
                            }
                        } else if hf == 7.0 && hw == 2 {
                            let b = h.str_()?;
                            if let Some(ht) = me.http.as_mut() {
                                ht.body = Some(b);
                            }
                        } else {
                            h.skip(hw)?;
                        }
                    }
                } else {
                    o.skip(ow)?;
                }
            }
        } else {
            mr.skip(mw)?;
        }
    }
    Ok(me)
}

pub fn parse_descriptor_set(data: &[u8]) -> R<ProtoModel> {
    let mut m = ProtoModel::default();
    let mut top = Reader::new(data);
    while top.more() {
        let (f, wt) = tag(&mut top)?;
        if f != 1.0 || wt != 2 {
            top.skip(wt)?;
            continue;
        }
        let mut fr = top.len()?;
        let mut pkg = String::new();
        let mut msgs: Vec<Reader> = vec![];
        let mut enums: Vec<Reader> = vec![];
        let mut svcs: Vec<Reader> = vec![];
        while fr.more() {
            // the package may follow the messages in the wire order: collect first, then resolve scopes
            let (ff, fw) = tag(&mut fr)?;
            if ff == 2.0 && fw == 2 {
                pkg = fr.str_()?;
            } else if ff == 4.0 && fw == 2 {
                msgs.push(fr.len()?);
            } else if ff == 5.0 && fw == 2 {
                enums.push(fr.len()?);
            } else if ff == 6.0 && fw == 2 {
                svcs.push(fr.len()?);
            } else {
                fr.skip(fw)?;
            }
        }
        for r in msgs {
            read_msg(&mut m, r, &pkg, 0)?;
        }
        for r in enums {
            read_enum(&mut m, r, &pkg)?;
        }
        for mut r in svcs {
            let mut name = String::new();
            let mut methods: Vec<ProtoMethod> = vec![];
            while r.more() {
                let (sf, sw) = tag(&mut r)?;
                if sf == 1.0 && sw == 2 {
                    name = r.str_()?;
                } else if sf == 2.0 && sw == 2 {
                    let mr = r.len()?;
                    methods.push(read_method(mr, &pkg)?);
                } else {
                    r.skip(sw)?;
                }
            }
            m.services.push(ProtoService { full: qual(&pkg, &name), name, methods });
        }
    }
    Ok(m)
}

// ---- model -> params --------------------------------------------------------------------------------------------------------

fn resolve_name(m: &ProtoModel, name: &str, scope: &str) -> Option<String> {
    if let Some(rest) = name.strip_prefix('.') {
        return Some(rest.to_string());
    }
    let parts: Vec<&str> = if scope.is_empty() { vec![] } else { scope.split('.').collect() };
    for k in (0..=parts.len()).rev() {
        let mut segs: Vec<&str> = parts[..k].to_vec();
        segs.push(name);
        let cand = segs.join(".");
        if m.message(&cand).is_some() || m.enum_(&cand).is_some() {
            return Some(cand);
        }
    }
    if m.message(name).is_some() || m.enum_(name).is_some() {
        Some(name.to_string())
    } else {
        None
    }
}

fn empty_obj() -> Value {
    Value::Object(Map::new())
}

fn one_type(m: &ProtoModel, typ: &str, scope: &str, c: &mut Ctx, stack: &[String], where_: &str, budget: &mut i64) -> Value {
    if SCALAR_NAMES.contains(&typ) {
        if typ.contains("int") || typ.contains("fixed") {
            return json!({"type": "integer", "format": "int64"});
        }
        if typ == "bool" {
            return json!({"type": "boolean"});
        }
        if typ == "string" || typ == "bytes" {
            return json!({"type": "string"});
        }
        return json!({"type": "number"});
    }
    let ab = typ.strip_prefix('.');
    if ab == Some("google.protobuf.Timestamp") || typ == "google.protobuf.Timestamp" {
        return json!({"type": "string", "format": "date-time"});
    }
    let t = ab.unwrap_or(typ);
    if matches!(t, "google.protobuf.StringValue" | "google.protobuf.BytesValue") {
        return json!({"type": "string"});
    }
    if matches!(t, "google.protobuf.Int32Value" | "google.protobuf.Int64Value" | "google.protobuf.UInt32Value" | "google.protobuf.UInt64Value") {
        return json!({"type": "integer", "format": "int64"});
    }
    if t == "google.protobuf.BoolValue" {
        return json!({"type": "boolean"});
    }
    if t.starts_with("google.protobuf.") {
        return empty_obj();
    }
    let Some(full) = resolve_name(m, typ, scope) else {
        add_todo(c, where_, "unknown_type", &format!("type '{}' is not defined in the proto source (declared string)", clip(typ, 60)));
        return empty_obj();
    };
    if let Some(en) = m.enum_(&full) {
        return json!({"type": "string", "enum": uniq_strs(en.values.iter().cloned())});
    }
    msg_schema(m, &full, c, stack, where_, budget)
}

fn field_schema(m: &ProtoModel, f: &ProtoField, c: &mut Ctx, stack: &[String], where_: &str, budget: &mut i64) -> Value {
    if f.map.is_some() {
        return json!({"type": "object"});
    }
    let sch = one_type(m, &f.typ, &f.scope, c, stack, where_, budget);
    if f.repeated {
        json!({"type": "array", "items": sch})
    } else {
        sch
    }
}

fn msg_schema(m: &ProtoModel, full: &str, c: &mut Ctx, stack: &[String], where_: &str, budget: &mut i64) -> Value {
    let Some(msg) = m.message(full) else {
        return empty_obj();
    };
    if stack.iter().any(|x| x == full) {
        add_todo(c, where_, "cyclic_ref", &format!("message '{}' is recursive (declared string; refine or drop)", clip(full, 80)));
        return empty_obj();
    }
    let mut stop = stack.len() as i64 > c.lim.max_ref_depth;
    if !stop {
        *budget -= 1;
        stop = *budget <= 0;
    }
    if stop {
        add_todo(c, where_, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)");
        return empty_obj();
    }
    let mut st = stack.to_vec();
    st.push(full.to_string());
    let mut properties = Map::new();
    let mut required: Vec<Value> = vec![];
    for f in &msg.fields {
        if f.behavior.iter().any(|b| b == "OUTPUT_ONLY") {
            continue;
        }
        if f.name != "__proto__" {
            let sch = field_schema(m, f, c, &st, &format!("{}.{}", where_, f.name), budget);
            properties.insert(f.name.clone(), sch);
        }
        if f.behavior.iter().any(|b| b == "REQUIRED") {
            required.push(s(&f.name));
        }
    }
    json!({"type": "object", "properties": Value::Object(properties), "required": Value::Array(required)})
}

/// `source` is `.proto` text (a JSON string) or the bytes of a binary FileDescriptorSet.
pub fn import_grpc(source: Source, opts: &Value) -> R<Value> {
    let mut c = new_ctx("grpc", source, opts)?;
    let m = match source {
        Source::Json(Value::String(t)) => parse_proto(t)?,
        Source::Bytes(b) => parse_descriptor_set(b)?,
        Source::Json(_) => return Err(bad("a gRPC source is .proto text or a binary FileDescriptorSet")),
    };
    let mut svcs: Vec<&ProtoService> = m.services.iter().collect();
    svcs.sort_by(|a, b| a.full.as_bytes().cmp(b.full.as_bytes()));
    for svc in svcs {
        let mut ms: Vec<&ProtoMethod> = svc.methods.iter().collect();
        ms.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for me in ms {
            let where_ = format!("{}/{}", svc.name, me.name);
            c.root = Value::Null;
            let mut bud = new_budget(&c);
            let inp = resolve_name(&m, &me.input, &me.scope).unwrap_or_else(|| me.input.strip_prefix('.').unwrap_or(&me.input).to_string());
            let mut nb = c.lim.max_ref_nodes;
            let schema = msg_schema(&m, &inp, &mut c, &[], &where_, &mut nb);
            let mut params = Map::new();
            if let Value::Object(so) = &schema {
                if so.contains_key("properties") {
                    flatten_object(so, &mut c, &mut bud, &where_, &mut params, &[], true)?;
                } else if m.message(&inp).is_none() && !inp.starts_with("google.protobuf.") {
                    add_todo(&mut c, &where_, "unknown_type", &format!("request type '{}' is not defined in the source (no parameters)", clip(&me.input, 60)));
                }
            }
            let hm = me.http.as_ref().map(|h| h.method.as_str());
            let idem = me.idem.as_deref();
            let effects: &[&str] = match hm {
                Some("GET") => &["read"],
                Some("DELETE") => &["delete"],
                Some("POST") => &["create"],
                Some("PUT") | Some("PATCH") => &["update"],
                _ => {
                    if idem == Some("NO_SIDE_EFFECTS") {
                        &["read"]
                    } else {
                        &["update"]
                    }
                }
            };
            let natural = matches!(idem, Some("NO_SIDE_EFFECTS") | Some("IDEMPOTENT")) || matches!(hm, Some("GET") | Some("PUT") | Some("DELETE"));
            let mut traits: Option<Vec<String>> = None;
            if me.cs || me.ss {
                traits = Some(with_trait(traits, "pca.bulk"));
                add_todo(&mut c, &where_, "streaming", "a streaming method: acts on many messages (pca.bulk added)");
            }
            let mut bindings = json!({"grpc": {"service": clip(&svc.full, 250), "method": clip(&me.name, 250)}});
            if let Some(h) = &me.http {
                if !h.path.is_empty() {
                    bindings["http"] = json!({"method": h.method, "path": clip(&h.path, 250)});
                }
            }
            let title = s(&CAMEL.replace_all(&me.name, "$1 $2"));
            emit_def(
                &mut c,
                &format!("{} {}", svc.name, me.name),
                effects,
                "one",
                params,
                bindings,
                EmitOpts {
                    verb: None,
                    title: Some(&title),
                    description: None,
                    idempotency: if natural { Some(json!({"mode": "natural"})) } else { None },
                    traits,
                    no_alias: false,
                },
            )?;
        }
    }
    Ok(finish(c))
}
