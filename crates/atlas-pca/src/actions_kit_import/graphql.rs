//! GraphQL SDL or introspection JSON to drafts (native port of the GraphQL importer of the reference action-kit package). Query fields are
//! reads, Mutation fields are writes, Subscription fields are streaming reads; arguments and input objects are flattened to dotted params.
//! There is no method signal, so everything stays `unreviewed`. A [`GqlSchema`] renders as `{types: [[name, typedef]...], query?, mutation?,
//! subscription?}`; a typedef is `{kind, name, fields: [{name, args, type, desc?, deprecated}], values}`; a type is
//! `{k: "named"|"list"|"nonnull", ...}`.

use super::common::{
    add_todo, clip, emit_def, finish, flatten_object, g, kerr, new_budget, new_ctx, s, uniq_strs, with_trait, ActionKitError, Budget, Ctx, EmitOpts, Source, R,
};
use serde_json::{json, Map, Value};
use std::collections::HashMap;

static NULL: Value = Value::Null;

fn bad(msg: impl Into<String>) -> ActionKitError {
    kerr("bad_source", msg)
}

// ---- model ------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum GqlType {
    Named(String),
    List(Box<GqlType>),
    NonNull(Box<GqlType>),
}

impl GqlType {
    pub fn to_json(&self) -> Value {
        match self {
            GqlType::Named(n) => json!({"k": "named", "name": n}),
            GqlType::List(o) => json!({"k": "list", "of": o.to_json()}),
            GqlType::NonNull(o) => json!({"k": "nonnull", "of": o.to_json()}),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GqlArg {
    pub name: String,
    pub ty: GqlType,
    pub desc: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GqlField {
    pub name: String,
    pub args: Vec<GqlArg>,
    pub ty: GqlType,
    pub desc: Option<String>,
    pub deprecated: bool,
}

#[derive(Clone, Debug)]
pub struct GqlTypeDef {
    pub kind: String,
    pub name: String,
    pub fields: Vec<GqlField>,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GqlSchema {
    pub types: Vec<GqlTypeDef>,
    idx: HashMap<String, usize>,
    pub query: Option<String>,
    pub mutation: Option<String>,
    pub subscription: Option<String>,
}

impl GqlSchema {
    pub fn get(&self, name: &str) -> Option<&GqlTypeDef> {
        self.idx.get(name).map(|&i| &self.types[i])
    }

    /// `types[name] = d`: a repeated name keeps its first position.
    fn put(&mut self, d: GqlTypeDef) {
        match self.idx.get(&d.name) {
            Some(&i) => self.types[i] = d,
            None => {
                self.idx.insert(d.name.clone(), self.types.len());
                self.types.push(d);
            }
        }
    }

    /// A repeated definition (an `extend` or a duplicate) adds its members to the first.
    fn merge(&mut self, d: GqlTypeDef) {
        match self.idx.get(&d.name) {
            Some(&i) => {
                self.types[i].fields.extend(d.fields);
                self.types[i].values.extend(d.values);
            }
            None => self.put(d),
        }
    }

    pub fn to_json(&self) -> Value {
        let types: Vec<Value> = self
            .types
            .iter()
            .map(|t| {
                let fields: Vec<Value> = t
                    .fields
                    .iter()
                    .map(|f| {
                        let args: Vec<Value> = f
                            .args
                            .iter()
                            .map(|a| {
                                let mut m = Map::new();
                                m.insert("name".into(), s(&a.name));
                                m.insert("type".into(), a.ty.to_json());
                                if let Some(d) = &a.desc {
                                    m.insert("desc".into(), s(d));
                                }
                                Value::Object(m)
                            })
                            .collect();
                        let mut m = Map::new();
                        m.insert("name".into(), s(&f.name));
                        m.insert("args".into(), Value::Array(args));
                        m.insert("type".into(), f.ty.to_json());
                        m.insert("deprecated".into(), Value::Bool(f.deprecated));
                        if let Some(d) = &f.desc {
                            m.insert("desc".into(), s(d));
                        }
                        Value::Object(m)
                    })
                    .collect();
                let mut m = Map::new();
                m.insert("kind".into(), s(&t.kind));
                m.insert("name".into(), s(&t.name));
                m.insert("fields".into(), Value::Array(fields));
                m.insert("values".into(), Value::Array(t.values.iter().map(|v| s(v)).collect()));
                Value::Array(vec![s(&t.name), Value::Object(m)])
            })
            .collect();
        let mut out = Map::new();
        out.insert("types".into(), Value::Array(types));
        if let Some(q) = &self.query {
            out.insert("query".into(), s(q));
        }
        if let Some(q) = &self.mutation {
            out.insert("mutation".into(), s(q));
        }
        if let Some(q) = &self.subscription {
            out.insert("subscription".into(), s(q));
        }
        Value::Object(out)
    }
}

// ---- lexer ------------------------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    Str,
    Name,
    Int,
    Punct,
    Eof,
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
        return Err(kerr("import_limit", "the GraphQL source has too many tokens"));
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
        if " \t\n\r,\u{feff}".contains(ch) {
            i += 1;
            continue;
        }
        if ch == '#' {
            while i < n && c[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '"' {
            if starts(&c, i, "\"\"\"") {
                let mut j = i + 3;
                let mut t = String::new();
                while j < n && !starts(&c, j, "\"\"\"") {
                    if starts(&c, j, "\\\"\"\"") {
                        t.push_str("\"\"\"");
                        j += 4;
                    } else {
                        t.push(c[j]);
                        j += 1;
                    }
                }
                if j >= n {
                    return Err(bad("unterminated GraphQL block string"));
                }
                push(&mut out, max_tokens, K::Str, t)?;
                i = j + 3;
            } else {
                let mut j = i + 1;
                let mut t = String::new();
                while j < n && c[j] != '"' {
                    if c[j] == '\n' {
                        return Err(bad("unterminated GraphQL string"));
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
                    return Err(bad("unterminated GraphQL string"));
                }
                push(&mut out, max_tokens, K::Str, t)?;
                i = j + 1;
            }
            continue;
        }
        if ch == '_' || ch.is_ascii_alphabetic() {
            let mut j = i + 1;
            while j < n && (c[j] == '_' || c[j].is_ascii_alphanumeric()) {
                j += 1;
            }
            push(&mut out, max_tokens, K::Name, c[i..j].iter().collect())?;
            i = j;
            continue;
        }
        if ch == '-' || ch.is_ascii_digit() {
            let mut j = i + 1;
            while j < n && matches!(c[j], '-' | '+' | '.' | '0'..='9' | 'e' | 'E') {
                j += 1;
            }
            push(&mut out, max_tokens, K::Int, c[i..j].iter().collect())?;
            i = j;
            continue;
        }
        if starts(&c, i, "...") {
            push(&mut out, max_tokens, K::Punct, "...".to_string())?;
            i += 3;
            continue;
        }
        if "!$&():=@[]{|}".contains(ch) {
            push(&mut out, max_tokens, K::Punct, ch.to_string())?;
            i += 1;
            continue;
        }
        return Err(bad(format!("unexpected character in GraphQL source at offset {i}")));
    }
    push(&mut out, max_tokens, K::Eof, String::new())?;
    Ok(out)
}

// ---- parser -----------------------------------------------------------------------------------------------------------------

struct P {
    i: usize,
    toks: Vec<Tok>,
    schema: GqlSchema,
    max_depth: usize,
}

impl P {
    fn cur(&self) -> &Tok {
        &self.toks[self.i.min(self.toks.len() - 1)]
    }

    fn at_eof(&self) -> bool {
        self.cur().k == K::Eof
    }

    fn next(&mut self) -> Tok {
        let t = self.cur().clone();
        if t.k != K::Eof {
            self.i += 1;
        }
        t
    }

    fn is_(&self, v: &str) -> bool {
        let t = self.cur();
        t.k != K::Str && t.v == v
    }

    fn eat(&mut self, v: &str) -> bool {
        if self.is_(v) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, v: &str) -> R<()> {
        if self.eat(v) {
            Ok(())
        } else {
            Err(bad(format!("GraphQL parse error: expected '{v}' near '{}'", clip(&self.cur().v, 30))))
        }
    }

    fn name(&mut self) -> R<String> {
        let t = self.next();
        if t.k != K::Name {
            return Err(bad(format!("GraphQL parse error: expected a name near '{}'", clip(&t.v, 30))));
        }
        Ok(t.v)
    }

    fn desc(&mut self) -> Option<String> {
        if self.cur().k == K::Str {
            Some(self.next().v)
        } else {
            None
        }
    }

    fn type_(&mut self, depth: usize) -> R<GqlType> {
        if depth > self.max_depth {
            return Err(kerr("import_limit", "GraphQL type nesting is too deep"));
        }
        let t = if self.eat("[") {
            let inner = self.type_(depth + 1)?;
            self.expect("]")?;
            GqlType::List(Box::new(inner))
        } else {
            GqlType::Named(self.name()?)
        };
        Ok(if self.eat("!") { GqlType::NonNull(Box::new(t)) } else { t })
    }

    fn value(&mut self, depth: usize) -> R<()> {
        if depth > self.max_depth {
            return Err(kerr("import_limit", "GraphQL value nesting is too deep"));
        }
        let t = self.cur().clone();
        if matches!(t.k, K::Str | K::Int | K::Name) {
            self.i += 1;
            return Ok(());
        }
        if self.eat("[") {
            while !self.is_("]") && !self.at_eof() {
                self.value(depth + 1)?;
            }
            return self.expect("]");
        }
        if self.eat("{") {
            while !self.is_("}") && !self.at_eof() {
                self.name()?;
                self.expect(":")?;
                self.value(depth + 1)?;
            }
            return self.expect("}");
        }
        if self.eat("$") {
            self.name()?;
            return Ok(());
        }
        Err(bad(format!("GraphQL parse error: unexpected '{}'", clip(&t.v, 30))))
    }

    fn directives(&mut self) -> R<bool> {
        let mut deprecated = false;
        while self.eat("@") {
            if self.name()? == "deprecated" {
                deprecated = true;
            }
            if self.eat("(") {
                while !self.is_(")") && !self.at_eof() {
                    self.name()?;
                    self.expect(":")?;
                    self.value(0)?;
                }
                self.expect(")")?;
            }
        }
        Ok(deprecated)
    }

    fn args(&mut self) -> R<Vec<GqlArg>> {
        let mut out = vec![];
        if !self.eat("(") {
            return Ok(out);
        }
        while !self.is_(")") {
            if self.at_eof() {
                return Err(bad("GraphQL parse error: unterminated argument list"));
            }
            let desc = self.desc();
            let name = self.name()?;
            self.expect(":")?;
            let ty = self.type_(0)?;
            if self.eat("=") {
                self.value(0)?;
            }
            self.directives()?;
            out.push(GqlArg { name, ty, desc: desc.filter(|d| !d.is_empty()) });
        }
        self.expect(")")?;
        Ok(out)
    }

    fn fields(&mut self, inp: bool) -> R<Vec<GqlField>> {
        let mut out = vec![];
        if !self.eat("{") {
            return Ok(out);
        }
        while !self.is_("}") {
            if self.at_eof() {
                return Err(bad("GraphQL parse error: unterminated field list"));
            }
            let desc = self.desc();
            let name = self.name()?;
            let args = if inp { vec![] } else { self.args()? };
            self.expect(":")?;
            let ty = self.type_(0)?;
            if inp && self.eat("=") {
                self.value(0)?;
            }
            let deprecated = self.directives()?;
            out.push(GqlField { name, args, ty, desc: desc.filter(|d| !d.is_empty()), deprecated });
        }
        self.expect("}")?;
        Ok(out)
    }

    fn def_(&mut self) -> R<()> {
        self.desc();
        let mut kw = self.name()?;
        while kw == "extend" {
            self.desc();
            kw = self.name()?;
        }
        match kw.as_str() {
            "schema" => {
                self.directives()?;
                self.expect("{")?;
                while !self.is_("}") {
                    if self.at_eof() {
                        return Err(bad("GraphQL parse error: unterminated schema block"));
                    }
                    let op = self.name()?;
                    self.expect(":")?;
                    let ty = self.name()?;
                    match op.as_str() {
                        "query" => self.schema.query = Some(ty),
                        "mutation" => self.schema.mutation = Some(ty),
                        "subscription" => self.schema.subscription = Some(ty),
                        _ => {}
                    }
                }
                self.expect("}")
            }
            "scalar" => {
                let n = self.name()?;
                self.directives()?;
                self.schema.merge(GqlTypeDef { kind: "scalar".into(), name: n, fields: vec![], values: vec![] });
                Ok(())
            }
            "directive" => {
                self.expect("@")?;
                self.name()?;
                self.args()?;
                if self.cur().v == "repeatable" {
                    self.i += 1;
                }
                if self.cur().v == "on" {
                    self.i += 1;
                }
                self.eat("|");
                self.name()?;
                while self.eat("|") {
                    self.name()?;
                }
                Ok(())
            }
            "type" | "interface" | "input" => {
                let n = self.name()?;
                if self.cur().v == "implements" {
                    self.i += 1;
                    self.eat("&");
                    self.name()?;
                    while self.eat("&") {
                        self.name()?;
                    }
                }
                self.directives()?;
                let kind = match kw.as_str() {
                    "type" => "object",
                    "input" => "input",
                    _ => "interface",
                };
                let fields = self.fields(kw == "input")?;
                self.schema.merge(GqlTypeDef { kind: kind.into(), name: n, fields, values: vec![] });
                Ok(())
            }
            "union" => {
                let n = self.name()?;
                self.directives()?;
                if self.eat("=") {
                    self.eat("|");
                    self.name()?;
                    while self.eat("|") {
                        self.name()?;
                    }
                }
                self.schema.merge(GqlTypeDef { kind: "union".into(), name: n, fields: vec![], values: vec![] });
                Ok(())
            }
            "enum" => {
                let n = self.name()?;
                self.directives()?;
                let mut values: Vec<String> = vec![];
                if self.eat("{") {
                    while !self.is_("}") {
                        if self.at_eof() {
                            return Err(bad("GraphQL parse error: unterminated enum"));
                        }
                        self.desc();
                        values.push(self.name()?);
                        self.directives()?;
                    }
                    self.expect("}")?;
                }
                self.schema.merge(GqlTypeDef { kind: "enum".into(), name: n, fields: vec![], values });
                Ok(())
            }
            _ => Err(bad(format!("GraphQL parse error: unsupported definition '{}' (only type-system definitions are imported)", clip(&kw, 30)))),
        }
    }
}

pub fn parse_graphql_sdl(src: &str) -> R<GqlSchema> {
    parse_with(src, 2_000_000)
}

fn parse_with(src: &str, max_tokens: usize) -> R<GqlSchema> {
    let toks = lex(src, max_tokens)?;
    let mut p = P { i: 0, toks, schema: GqlSchema::default(), max_depth: 32 };
    while !p.at_eof() {
        p.def_()?;
    }
    Ok(p.schema)
}

// ---- introspection -> model -------------------------------------------------------------------------------------------------

fn introspect_type(t: &Value, depth: usize) -> R<GqlType> {
    if depth > 16 || !t.is_object() {
        return Err(bad("malformed introspection type reference"));
    }
    let of = g(t, "ofType").unwrap_or(&NULL);
    match g(t, "kind").and_then(Value::as_str) {
        Some("NON_NULL") => return Ok(GqlType::NonNull(Box::new(introspect_type(of, depth + 1)?))),
        Some("LIST") => return Ok(GqlType::List(Box::new(introspect_type(of, depth + 1)?))),
        _ => {}
    }
    match g(t, "name").and_then(Value::as_str) {
        Some(n) => Ok(GqlType::Named(n.to_string())),
        None => Err(bad("malformed introspection type reference")),
    }
}

fn kind_of(k: &str) -> Option<&'static str> {
    Some(match k {
        "OBJECT" => "object",
        "INPUT_OBJECT" => "input",
        "ENUM" => "enum",
        "SCALAR" => "scalar",
        "INTERFACE" => "interface",
        "UNION" => "union",
        _ => return None,
    })
}

fn field_of(f: &Value) -> R<Option<GqlField>> {
    let name = match g(f, "name").and_then(Value::as_str) {
        Some(n) if f.is_object() => n.to_string(),
        _ => return Ok(None),
    };
    let mut args = vec![];
    if let Some(Value::Array(raw)) = g(f, "args") {
        for a in raw {
            if let Some(an) = g(a, "name").and_then(Value::as_str) {
                let ty = introspect_type(g(a, "type").unwrap_or(&NULL), 0)?;
                args.push(GqlArg { name: an.to_string(), ty, desc: g(a, "description").and_then(Value::as_str).map(String::from) });
            }
        }
    }
    let ty = match g(f, "type") {
        None => GqlType::Named("String".into()),
        Some(t) => introspect_type(t, 0)?,
    };
    Ok(Some(GqlField {
        name,
        args,
        ty,
        desc: g(f, "description").and_then(Value::as_str).map(String::from),
        deprecated: matches!(g(f, "isDeprecated"), Some(Value::Bool(true))),
    }))
}

pub fn from_introspection(doc: &Value) -> R<GqlSchema> {
    let root = match g(doc, "data") {
        Some(d) if d.is_object() => d,
        _ => doc,
    };
    let sch = g(root, "__schema").filter(|x| x.is_object());
    let (sch, types) = match sch.and_then(|x| g(x, "types").and_then(Value::as_array).map(|t| (x, t))) {
        Some(p) => p,
        None => return Err(bad("not a GraphQL introspection result (no __schema.types)")),
    };
    let mut out = GqlSchema::default();
    let root_name = |k: &str| -> Option<String> {
        g(sch, k).filter(|x| x.is_object()).and_then(|x| g(x, "name")).and_then(Value::as_str).filter(|n| !n.is_empty()).map(String::from)
    };
    out.query = root_name("queryType");
    out.mutation = root_name("mutationType");
    out.subscription = root_name("subscriptionType");
    for t in types {
        let (name, kindv) = match (g(t, "name").and_then(Value::as_str), g(t, "kind").and_then(Value::as_str)) {
            (Some(n), Some(k)) if t.is_object() => (n, k),
            _ => continue,
        };
        if name.starts_with("__") {
            continue;
        }
        let Some(kind) = kind_of(kindv) else { continue };
        let raw = if kind == "input" { g(t, "inputFields") } else { g(t, "fields") };
        let mut fields = vec![];
        if let Some(Value::Array(rs)) = raw {
            for x in rs {
                if let Some(f) = field_of(x)? {
                    fields.push(f);
                }
            }
        }
        let mut values = vec![];
        if let Some(Value::Array(ev)) = g(t, "enumValues") {
            for e in ev {
                if let Some(n) = g(e, "name").and_then(Value::as_str) {
                    values.push(n.to_string());
                }
            }
        }
        out.put(GqlTypeDef { kind: kind.into(), name: name.to_string(), fields, values });
    }
    Ok(out)
}

// ---- model -> JSON-schema-like -> params ------------------------------------------------------------------------------------

fn scalar_schema(name: &str) -> Option<Value> {
    Some(match name {
        "Int" => json!({"type": "integer", "format": "int32"}),
        "String" | "ID" => json!({"type": "string"}),
        "Boolean" => json!({"type": "boolean"}),
        "Float" => json!({"type": "number"}),
        "Date" => json!({"type": "string", "format": "date"}),
        "DateTime" => json!({"type": "string", "format": "date-time"}),
        "Email" => json!({"type": "string", "format": "email"}),
        "UUID" => json!({"type": "string", "format": "uuid"}),
        "URL" | "URI" => json!({"type": "string", "format": "url"}),
        _ => return None,
    })
}

fn with_desc(r: Value, desc: &Option<String>) -> Value {
    let mut m = match r {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    if let Some(d) = desc {
        if !d.is_empty() {
            m.insert("description".into(), s(d));
        }
    }
    Value::Object(m)
}

fn schema_of(t: &GqlType, gs: &GqlSchema, c: &mut Ctx, bud: &mut Budget, stack: &[String], where_: &str) -> (Value, bool) {
    let mut nonnull = false;
    let mut cur = t;
    while let GqlType::NonNull(of) = cur {
        nonnull = true;
        cur = of;
    }
    let name = match cur {
        GqlType::List(of) => {
            let (items, _) = schema_of(of, gs, c, bud, stack, where_);
            return (json!({"type": "array", "items": items}), nonnull);
        }
        GqlType::Named(n) => n,
        GqlType::NonNull(_) => return (Value::Object(Map::new()), nonnull),
    };
    let spent = bud.left <= 0;
    bud.left -= 1;
    if spent {
        if !bud.exhausted {
            bud.exhausted = true;
            add_todo(c, where_, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)");
        }
        return (Value::Object(Map::new()), nonnull);
    }
    if let Some(v) = scalar_schema(name) {
        return (v, nonnull);
    }
    let Some(d) = gs.get(name) else {
        add_todo(c, where_, "unknown_type", &format!("type '{}' is not defined in the schema (declared string)", clip(name, 60)));
        return (Value::Object(Map::new()), nonnull);
    };
    match d.kind.as_str() {
        "enum" => (json!({"type": "string", "enum": uniq_strs(d.values.iter().cloned())}), nonnull),
        "scalar" => (json!({"type": "string"}), nonnull),
        "input" => {
            if stack.iter().any(|x| x == name) {
                add_todo(c, where_, "cyclic_ref", &format!("input type '{}' is recursive (declared string; refine or drop)", clip(name, 60)));
                return (Value::Object(Map::new()), nonnull);
            }
            let mut st = stack.to_vec();
            st.push(name.clone());
            let mut properties = Map::new();
            let mut required: Vec<Value> = vec![];
            for f in &d.fields {
                let (r, nn) = schema_of(&f.ty, gs, c, bud, &st, where_);
                if f.name != "__proto__" {
                    // assigning `__proto__` on a JS object sets its prototype: never a member
                    properties.insert(f.name.clone(), with_desc(r, &f.desc));
                }
                if nn {
                    required.push(s(&f.name));
                }
            }
            (json!({"type": "object", "properties": Value::Object(properties), "required": Value::Array(required)}), nonnull)
        }
        _ => {
            add_todo(c, where_, "output_type", &format!("type '{}' is an output type and cannot be an argument (declared string)", clip(name, 60)));
            (Value::Object(Map::new()), nonnull)
        }
    }
}

/// `source` is SDL text (a JSON string) or an introspection result (parsed JSON).
pub fn import_graphql(source: &Value, opts: &Value) -> R<Value> {
    let mut c = new_ctx("graphql", Source::Json(source), opts)?;
    let gs = match source {
        Value::String(t) => parse_graphql_sdl(t)?,
        _ => from_introspection(source)?,
    };
    let roots = [
        (gs.query.clone().unwrap_or_else(|| "Query".into()), "query"),
        (gs.mutation.clone().unwrap_or_else(|| "Mutation".into()), "mutation"),
        (gs.subscription.clone().unwrap_or_else(|| "Subscription".into()), "subscription"),
    ];
    for (root_name, op) in roots.iter() {
        let Some(rt) = gs.get(root_name) else { continue };
        let mut fs: Vec<&GqlField> = rt.fields.iter().collect();
        fs.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for f in fs {
            let where_ = format!("{} {}", op, clip(&f.name, 80));
            c.root = Value::Null;
            let mut bud = new_budget(&c);
            let mut properties = Map::new();
            let mut required: Vec<Value> = vec![];
            for a in &f.args {
                let (r, nn) = schema_of(&a.ty, &gs, &mut c, &mut bud, &[], &format!("{}({})", where_, a.name));
                if a.name != "__proto__" {
                    properties.insert(a.name.clone(), with_desc(r, &a.desc));
                }
                if nn {
                    required.push(s(&a.name));
                }
            }
            let mut sch = Map::new();
            sch.insert("type".into(), s("object"));
            sch.insert("properties".into(), Value::Object(properties));
            sch.insert("required".into(), Value::Array(required));
            let mut params = Map::new();
            flatten_object(&sch, &mut c, &mut bud, &where_, &mut params, &[], true)?;
            if f.deprecated {
                add_todo(&mut c, &where_, "deprecated", "the field is marked @deprecated");
            }
            let desc_v = f.desc.as_ref().map(|d| s(d));
            let title = match &f.desc {
                Some(d) if !d.is_empty() => s(d.split('\n').next().unwrap_or("")),
                _ => s(&f.name),
            };
            let is_mut = *op == "mutation";
            emit_def(
                &mut c,
                &f.name,
                if is_mut { &["update"] } else { &["read"] },
                "one",
                params,
                json!({"graphql": {"op": op, "field": clip(&f.name, 200)}}),
                EmitOpts {
                    verb: None,
                    title: Some(&title),
                    description: desc_v.as_ref(),
                    idempotency: if is_mut { None } else { Some(json!({"mode": "natural"})) },
                    traits: if *op == "subscription" { Some(with_trait(None, "pca.bulk")) } else { None },
                    no_alias: false,
                },
            )?;
        }
    }
    Ok(finish(c))
}
