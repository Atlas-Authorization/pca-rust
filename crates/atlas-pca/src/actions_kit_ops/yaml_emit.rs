//! The YAML text the reference writes for an action pack (`defsToYaml`): a line-for-line port of the default stringifier of the `yaml`
//! package (v2, core schema, 80 columns): plain, quoted and block scalars, folding, escapes, anchors and aliases for repeated containers.
//!
//! Strings are processed as UTF-16 code units (an astral character is two surrogate units) because the reference measures and folds in
//! code units. [`Y::Str`] therefore holds units, so a JavaScript string with a lone surrogate can be written (it is escaped). Comments,
//! tags, flow collections and custom schemas are not produced by the reference for plain data and are not ported.

use crate::intent_v2::js_number_string;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::LazyLock;

type U = Vec<u16>;

const LINE_WIDTH: i64 = 80;
const MIN_CONTENT_WIDTH: i64 = 20;
const DQ_MIN_MULTILINE: usize = 40;
const NL: u16 = b'\n' as u16;
const SP: u16 = b' ' as u16;
const TAB: u16 = b'\t' as u16;
const BS: u16 = b'\\' as u16;

fn u(s: &str) -> U {
    s.encode_utf16().collect()
}

fn ch(c: char) -> u16 {
    c as u16
}

fn at(s: &[u16], i: i64) -> Option<u16> {
    if i >= 0 && (i as usize) < s.len() {
        Some(s[i as usize])
    } else {
        None
    }
}

/// Python slice `s[a:b]` (negative indexes count from the end, out-of-range indexes clamp).
fn sl(s: &[u16], a: i64, b: i64) -> U {
    let n = s.len() as i64;
    let norm = |x: i64| if x < 0 { (x + n).max(0) } else { x.min(n) };
    let (a, b) = (norm(a), norm(b));
    if a >= b {
        U::new()
    } else {
        s[a as usize..b as usize].to_vec()
    }
}

fn is_lt(c: u16) -> bool {
    matches!(c, 0x0A | 0x0D | 0x2028 | 0x2029)
}

// ---- the node graph -----------------------------------------------------------------------------------------------------------

/// Plain data for the writer. A container held by two places (the same `Rc`) is written once with an anchor and then as aliases (cycles
/// too), like the reference does for a repeated object. `Str` holds UTF-16 code units.
#[derive(Clone)]
pub enum Y {
    Null,
    Bool(bool),
    Num(f64),
    Str(Vec<u16>),
    Seq(Rc<RefCell<Vec<Y>>>),
    Map(Rc<RefCell<Vec<(Vec<u16>, Y)>>>),
}

impl Y {
    pub fn string(s: &str) -> Y {
        Y::Str(u(s))
    }

    pub fn seq(items: Vec<Y>) -> Y {
        Y::Seq(Rc::new(RefCell::new(items)))
    }

    pub fn map(pairs: Vec<(Vec<u16>, Y)>) -> Y {
        Y::Map(Rc::new(RefCell::new(pairs)))
    }

    /// A tree without sharing from a JSON value.
    pub fn from_value(v: &Value) -> Y {
        match v {
            Value::Null => Y::Null,
            Value::Bool(b) => Y::Bool(*b),
            Value::Number(n) => Y::Num(n.as_f64().unwrap_or(0.0)),
            Value::String(s) => Y::string(s),
            Value::Array(a) => Y::seq(a.iter().map(Y::from_value).collect()),
            Value::Object(o) => Y::map(o.iter().map(|(k, x)| (u(k), Y::from_value(x))).collect()),
        }
    }
}

enum K {
    Null,
    Bool(bool),
    Num(f64),
    Str(U),
    Seq(Vec<Item>),
    Map(Vec<(U, Item)>),
}

enum Item {
    Node(usize),
    Alias(String),
}

struct Node {
    anchor: Option<String>,
    k: K,
}

/// createNode with aliasDuplicateObjects: a container met twice becomes an anchor (named a1, a2, ... in the order the repeats are met)
/// on its first occurrence and an alias on every later one.
struct Builder {
    arena: Vec<Node>,
    seen: HashMap<usize, (Option<String>, usize)>,
    n: usize,
}

impl Builder {
    fn push(&mut self, k: K) -> usize {
        self.arena.push(Node { anchor: None, k });
        self.arena.len() - 1
    }

    fn visit(&mut self, ptr: usize) -> Result<Item, usize> {
        if let Some(r) = self.seen.get_mut(&ptr) {
            if r.0.is_none() {
                self.n += 1;
                r.0 = Some(format!("a{}", self.n));
            }
            return Ok(Item::Alias(r.0.clone().unwrap_or_default()));
        }
        let idx = self.push(K::Null);
        self.seen.insert(ptr, (None, idx));
        Err(idx)
    }

    fn node(&mut self, v: &Y) -> Item {
        match v {
            Y::Null => Item::Node(self.push(K::Null)),
            Y::Bool(b) => Item::Node(self.push(K::Bool(*b))),
            Y::Num(f) => Item::Node(self.push(K::Num(*f))),
            Y::Str(s) => Item::Node(self.push(K::Str(s.clone()))),
            Y::Map(m) => match self.visit(Rc::as_ptr(m) as *const () as usize) {
                Ok(a) => a,
                Err(idx) => {
                    let mut pairs = Vec::new();
                    for (k, x) in m.borrow().iter() {
                        let it = self.node(x);
                        pairs.push((k.clone(), it));
                    }
                    self.arena[idx].k = K::Map(pairs);
                    Item::Node(idx)
                }
            },
            Y::Seq(s) => match self.visit(Rc::as_ptr(s) as *const () as usize) {
                Ok(a) => a,
                Err(idx) => {
                    let mut items = Vec::new();
                    for x in s.borrow().iter() {
                        items.push(self.node(x));
                    }
                    self.arena[idx].k = K::Seq(items);
                    Item::Node(idx)
                }
            },
        }
    }

    fn finish(&mut self) {
        for (name, idx) in self.seen.values() {
            if let Some(n) = name {
                self.arena[*idx].anchor = Some(n.clone());
            }
        }
    }
}

// ---- UTF-16 helpers -----------------------------------------------------------------------------------------------------------

/// `JSON.stringify` of a string in the code unit domain (well-formed: lone surrogates are escaped).
fn json_string(s: &[u16]) -> U {
    let mut out = vec![ch('"')];
    let n = s.len();
    for (i, &c) in s.iter().enumerate() {
        let esc = |out: &mut U, t: &str| out.extend(t.encode_utf16());
        match c {
            0x22 => esc(&mut out, "\\\""),
            0x5C => esc(&mut out, "\\\\"),
            0x08 => esc(&mut out, "\\b"),
            0x0C => esc(&mut out, "\\f"),
            0x0A => esc(&mut out, "\\n"),
            0x0D => esc(&mut out, "\\r"),
            0x09 => esc(&mut out, "\\t"),
            c if c < 0x20 => esc(&mut out, &format!("\\u{c:04x}")),
            0xD800..=0xDBFF if i + 1 < n && (0xDC00..=0xDFFF).contains(&s[i + 1]) => out.push(c),
            0xDC00..=0xDFFF if i > 0 && (0xD800..=0xDBFF).contains(&s[i - 1]) => out.push(c),
            0xD800..=0xDFFF => esc(&mut out, &format!("\\u{c:04x}")),
            c => out.push(c),
        }
    }
    out.push(ch('"'));
    out
}

/// Every maximal run of newlines of `s` becomes `pre + run + post`; `skip_final` leaves a run that reaches the end of `s` alone.
fn sub_nl(s: &[u16], pre: &[u16], post: &[u16], skip_final: bool) -> U {
    let mut out = U::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != NL {
            out.push(s[i]);
            i += 1;
            continue;
        }
        let mut j = i;
        while j < s.len() && s[j] == NL {
            j += 1;
        }
        if skip_final && j == s.len() {
            out.extend_from_slice(&s[i..j]);
        } else {
            out.extend_from_slice(pre);
            out.extend_from_slice(&s[i..j]);
            out.extend_from_slice(post);
        }
        i = j;
    }
    out
}

fn cat(parts: &[&[u16]]) -> U {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

fn has(s: &[u16], c: u16) -> bool {
    s.contains(&c)
}

// ---- folding ------------------------------------------------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
enum Mode {
    Flow,
    Block,
    Quoted,
}

fn consume_more_indented(text: &[u16], mut i: i64, indent: usize) -> i64 {
    let mut end = i;
    let mut start = i + 1;
    let mut c = at(text, start);
    while c == Some(SP) || c == Some(TAB) {
        if i < start + indent as i64 {
            i += 1;
            c = at(text, i);
        } else {
            loop {
                i += 1;
                c = at(text, i);
                if c.is_none() || c == Some(NL) {
                    break;
                }
            }
            end = i;
            start = i + 1;
            c = at(text, start);
        }
    }
    end
}

/// The folded text and whether a line could not be folded (overflow, reported only when the scan completed).
fn fold(text: &[u16], indent: &[u16], mode: Mode, indent_at_start: Option<i64>) -> (U, bool) {
    let mut min_content = MIN_CONTENT_WIDTH;
    if min_content > LINE_WIDTH {
        min_content = 0;
    }
    let ilen = indent.len() as i64;
    let end_step = (1 + min_content).max(1 + LINE_WIDTH - ilen);
    if text.len() as i64 <= end_step {
        return (text.to_vec(), false);
    }
    let mut folds: Vec<i64> = Vec::new();
    let mut escaped: HashSet<i64> = HashSet::new();
    let mut end = LINE_WIDTH - ilen;
    if let Some(ias) = indent_at_start {
        if ias > LINE_WIDTH - 2i64.max(min_content) {
            folds.push(0);
        } else {
            end = LINE_WIDTH - ias;
        }
    }
    let mut split: Option<i64> = None;
    let mut prev: Option<u16> = None;
    let mut overflow = false;
    let mut i: i64 = -1;
    let (mut esc_start, mut esc_end) = (-1i64, -1i64);
    if mode == Mode::Block {
        i = consume_more_indented(text, i, indent.len());
        if i != -1 {
            end = i + end_step;
        }
    }
    loop {
        i += 1;
        let mut c = at(text, i);
        if c.is_none() {
            break;
        }
        if mode == Mode::Quoted && c == Some(BS) {
            esc_start = i;
            i += match at(text, i + 1) {
                Some(0x78) => 3,
                Some(0x75) => 5,
                Some(0x55) => 9,
                _ => 1,
            };
            esc_end = i;
        }
        if c == Some(NL) {
            if mode == Mode::Block {
                i = consume_more_indented(text, i, indent.len());
            }
            end = i + ilen + end_step;
            split = None;
        } else {
            if c == Some(SP) && prev.is_some_and(|p| !matches!(p, SP | NL | TAB)) && at(text, i + 1).is_some_and(|n| !matches!(n, SP | NL | TAB)) {
                split = Some(i);
            }
            if i >= end {
                if let Some(sp) = split {
                    folds.push(sp);
                    end = sp + end_step;
                    split = None;
                } else if mode == Mode::Quoted {
                    while prev == Some(SP) || prev == Some(TAB) {
                        prev = c;
                        i += 1;
                        c = at(text, i);
                        overflow = true;
                    }
                    let j = if i > esc_end + 1 { i - 2 } else { esc_start - 1 };
                    if escaped.contains(&j) {
                        return (text.to_vec(), false);
                    }
                    folds.push(j);
                    escaped.insert(j);
                    end = j + end_step;
                    split = None;
                } else {
                    overflow = true;
                }
            }
        }
        prev = c;
    }
    if folds.is_empty() {
        return (text.to_vec(), overflow);
    }
    let mut res = sl(text, 0, folds[0]);
    for (k, &f) in folds.iter().enumerate() {
        let nxt = folds.get(k + 1).copied().unwrap_or(0);
        let stop = if nxt != 0 { nxt } else { text.len() as i64 };
        if f == 0 {
            res = cat(&[&[NL], indent, &sl(text, 0, stop)]);
        } else {
            if mode == Mode::Quoted && escaped.contains(&f) {
                if let Some(c) = at(text, f) {
                    res.push(c);
                }
                res.push(BS);
            }
            res.extend(cat(&[&[NL], indent, &sl(text, f + 1, stop)]));
        }
    }
    (res, overflow)
}

// ---- context ------------------------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct Ctx {
    indent: U,
    indent_at_start: Option<i64>,
    implicit_key: bool,
    actual_string: bool,
    force_block_indent: bool,
    anchors: Rc<RefCell<HashSet<String>>>,
}

fn two_spaces() -> U {
    vec![SP, SP]
}

fn contains_doc_marker(s: &[u16]) -> bool {
    (0..s.len()).any(|i| (i == 0 || is_lt(s[i - 1])) && (s[i] == ch('%') || s[i..].starts_with(&u("---")) || s[i..].starts_with(&u("..."))))
}

fn line_len_over(s: &[u16], line_width: i64, indent_len: usize) -> bool {
    let limit = line_width - indent_len as i64;
    let n = s.len() as i64;
    if n <= limit {
        return false;
    }
    let mut start = 0i64;
    for i in 0..s.len() {
        if s[i] == NL {
            if i as i64 - start > limit {
                return true;
            }
            start = i as i64 + 1;
            if n - start <= limit {
                return false;
            }
        }
    }
    true
}

// ---- strings ------------------------------------------------------------------------------------------------------------------

fn indent_or_marker(ctx: &Ctx, value: &[u16]) -> U {
    if !ctx.indent.is_empty() {
        ctx.indent.clone()
    } else if contains_doc_marker(value) {
        two_spaces()
    } else {
        U::new()
    }
}

fn double_quoted(value: &[u16], ctx: &Ctx) -> U {
    let js = json_string(value);
    let implicit = ctx.implicit_key;
    let indent = indent_or_marker(ctx, value);
    let mut out = U::new();
    let mut start: i64 = 0;
    let mut i: i64 = 0;
    let n = js.len() as i64;
    while i < n {
        let mut c = js[i as usize];
        if c == SP && at(&js, i + 1) == Some(BS) && at(&js, i + 2) == Some(0x6E) {
            out.extend(sl(&js, start, i));
            out.extend(u("\\ "));
            i += 1;
            start = i;
            c = BS;
        }
        if c == BS {
            match at(&js, i + 1) {
                Some(0x75) => {
                    out.extend(sl(&js, start, i));
                    let code = String::from_utf16_lossy(&sl(&js, i + 2, i + 6));
                    match code.as_str() {
                        "0000" => out.extend(u("\\0")),
                        "0007" => out.extend(u("\\a")),
                        "000b" => out.extend(u("\\v")),
                        "001b" => out.extend(u("\\e")),
                        "0085" => out.extend(u("\\N")),
                        "00a0" => out.extend(u("\\_")),
                        "2028" => out.extend(u("\\L")),
                        "2029" => out.extend(u("\\P")),
                        c if c.starts_with("00") => {
                            out.extend(u("\\x"));
                            out.extend(u(&c[2..]));
                        }
                        _ => out.extend(sl(&js, i, i + 6)),
                    }
                    i += 5;
                    start = i + 1;
                }
                Some(0x6E) => {
                    if implicit || at(&js, i + 2) == Some(0x22) || js.len() < DQ_MIN_MULTILINE {
                        i += 1;
                    } else {
                        out.extend(sl(&js, start, i));
                        out.extend([NL, NL]);
                        while at(&js, i + 2) == Some(BS) && at(&js, i + 3) == Some(0x6E) && at(&js, i + 4) != Some(0x22) {
                            out.push(NL);
                            i += 2;
                        }
                        out.extend(&indent);
                        if at(&js, i + 2) == Some(SP) {
                            out.push(BS);
                        }
                        i += 1;
                        start = i + 1;
                    }
                }
                _ => i += 1,
            }
        }
        i += 1;
    }
    let out = if start != 0 { cat(&[&out, &sl(&js, start, n)]) } else { js };
    if implicit {
        out
    } else {
        fold(&out, &indent, Mode::Quoted, ctx.indent_at_start).0
    }
}

fn single_quoted(value: &[u16], ctx: &Ctx) -> U {
    let ws_nl = value.windows(2).any(|w| (matches!(w[0], SP | TAB) && w[1] == NL) || (w[0] == NL && matches!(w[1], SP | TAB)));
    if (ctx.implicit_key && has(value, NL)) || ws_nl {
        return double_quoted(value, ctx);
    }
    let indent = indent_or_marker(ctx, value);
    let mut esc = U::new();
    for &c in value {
        esc.push(c);
        if c == 0x27 {
            esc.push(c);
        }
    }
    let nl_indent = cat(&[&[NL], &indent]);
    let res = cat(&[&[0x27], &sub_nl(&esc, &[], &nl_indent, false), &[0x27]]);
    if ctx.implicit_key {
        res
    } else {
        fold(&res, &indent, Mode::Flow, ctx.indent_at_start).0
    }
}

fn quoted(value: &[u16], ctx: &Ctx) -> U {
    if has(value, 0x22) && !has(value, 0x27) {
        single_quoted(value, ctx)
    } else {
        double_quoted(value, ctx)
    }
}

/// `(\A|\n)([\t ][^\n\r  ]*)(?:([\n\t ]*)\n(?![\n\t ]))?` replaced by group 1 + group 2: a more-indented line loses its
/// leading and trailing newline (the writer's folded block style does not double those).
fn unfold_more_indented(s: &[u16]) -> U {
    let ws = |c: u16| c == SP || c == TAB;
    let n = s.len();
    let mut out = U::new();
    let (mut last, mut i) = (0usize, 0usize);
    while i < n {
        let g1 = if i == 0 && ws(s[0]) {
            Some(0)
        } else if s[i] == NL && i + 1 < n && ws(s[i + 1]) {
            Some(i + 1)
        } else {
            None
        };
        let Some(g1s) = g1 else {
            i += 1;
            continue;
        };
        let mut e = g1s;
        while e < n && !is_lt(s[e]) {
            e += 1;
        }
        let mut r = e;
        while r < n && (s[r] == NL || ws(s[r])) {
            r += 1;
        }
        let (g2, mend) = if r > e && s[r - 1] == NL { (&s[e..r - 1], r) } else { (&s[e..e], e) };
        out.extend_from_slice(&s[last..i]);
        out.extend_from_slice(&s[g1s..e]);
        out.extend_from_slice(g2);
        last = mend;
        i = mend;
    }
    out.extend_from_slice(&s[last..]);
    out
}

fn block_string(value: &[u16], ctx: &mut Ctx) -> U {
    let ends_nl_ws = {
        let mut k = value.len();
        while k > 0 && matches!(value[k - 1], SP | TAB) {
            k -= 1;
        }
        k < value.len() && k > 0 && value[k - 1] == NL
    };
    if ends_nl_ws {
        return quoted(value, ctx);
    }
    let indent = if !ctx.indent.is_empty() {
        ctx.indent.clone()
    } else if ctx.force_block_indent || contains_doc_marker(value) {
        two_spaces()
    } else {
        U::new()
    };
    let literal = !line_len_over(value, LINE_WIDTH, indent.len());
    if value.is_empty() {
        return u(if literal { "|\n" } else { ">\n" });
    }
    let mut end_start = value.len();
    while end_start > 0 && matches!(value[end_start - 1], NL | TAB | SP) {
        end_start -= 1;
    }
    let mut end: U = value[end_start..].to_vec();
    let nl = end.iter().position(|&c| c == NL);
    let chomp = match nl {
        None => "-",
        Some(p) if end.len() == value.len() || p != end.len() - 1 => "+",
        _ => "",
    };
    let mut value: U = value.to_vec();
    if !end.is_empty() {
        value.truncate(value.len() - end.len());
        if end.last() == Some(&NL) {
            end.pop();
        }
        end = sub_nl(&end, &[], &indent, true);
    }
    let (mut start_with_space, mut start_end, mut start_nl) = (false, 0usize, -1i64);
    while start_end < value.len() {
        match value[start_end] {
            SP => start_with_space = true,
            NL => start_nl = start_end as i64,
            _ => break,
        }
        start_end += 1;
    }
    let cut = if start_nl < start_end as i64 { start_nl + 1 } else { start_end as i64 };
    let mut start = sl(&value, 0, cut);
    if !start.is_empty() {
        value = value[start.len()..].to_vec();
        start = sub_nl(&start, &[], &indent, false);
    }
    let mut header = String::new();
    if start_with_space {
        header.push(if indent.is_empty() { '1' } else { '2' });
    }
    header.push_str(chomp);
    if !literal {
        let folded = sub_nl(&value, &[NL], &[], false);
        let folded = unfold_more_indented(&folded);
        let folded = sub_nl(&folded, &[], &indent, false);
        let (body, fell) = fold(&cat(&[&start, &folded, &end]), &indent, Mode::Block, Some(ctx.indent.len() as i64));
        if !fell {
            return cat(&[&u(">"), &u(&header), &[NL], &indent, &body]);
        }
    }
    let value = sub_nl(&value, &[], &indent, false);
    cat(&[&u("|"), &u(&header), &[NL], &indent, &start, &value, &end])
}

static TAG_TESTS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    [
        r"(?:~|[Nn]ull|NULL)?",
        r"(?:[Tt]rue|TRUE|[Ff]alse|FALSE)",
        r"0o[0-7]+",
        r"[-+]?[0-9]+",
        r"0x[0-9a-fA-F]+",
        r"(?:[-+]?\.(?:inf|Inf|INF)|\.nan|\.NaN|\.NAN)",
        r"[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+",
        r"[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)",
    ]
    .iter()
    .map(|p| regex::Regex::new(&format!(r"\A(?:{p})\z")).expect("static pattern"))
    .collect()
});

fn tag_test(s: &[u16]) -> bool {
    if s.iter().any(|&c| c > 0x7F) {
        return false;
    }
    let t = String::from_utf16_lossy(s);
    TAG_TESTS.iter().any(|r| r.is_match(&t))
}

/// `^[\n\t ,\[\]{}#&*!|>'"%@`]|^[?-]$|^[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]$`: text a plain scalar cannot carry.
fn plain_bad(v: &[u16]) -> bool {
    let n = v.len();
    if n == 0 {
        return false;
    }
    if "\n\t ,[]{}#&*!|>'\"%@`".encode_utf16().any(|c| c == v[0]) {
        return true;
    }
    if (v[0] == ch('?') || v[0] == ch('-')) && (n == 1 || matches!(v[1], SP | TAB)) {
        return true;
    }
    if (0..n - 1).any(|i| {
        ((v[i] == NL || v[i] == ch(':')) && matches!(v[i + 1], SP | TAB))
            || (matches!(v[i], SP | TAB) && v[i + 1] == NL)
            || (matches!(v[i], NL | TAB | SP) && v[i + 1] == ch('#'))
    }) {
        return true;
    }
    matches!(v[n - 1], NL | TAB | SP) || v[n - 1] == ch(':')
}

fn plain(value: &[u16], ctx: &mut Ctx) -> U {
    let has_nl = has(value, NL);
    if ctx.implicit_key && has_nl {
        return quoted(value, ctx);
    }
    if plain_bad(value) {
        return if ctx.implicit_key || !has_nl { quoted(value, ctx) } else { block_string(value, ctx) };
    }
    if !ctx.implicit_key && has_nl {
        return block_string(value, ctx);
    }
    if contains_doc_marker(value) {
        if ctx.indent.is_empty() {
            ctx.force_block_indent = true;
            return block_string(value, ctx);
        }
        if ctx.implicit_key && ctx.indent == two_spaces() {
            return quoted(value, ctx);
        }
    }
    let s = sub_nl(value, &[], &cat(&[&[NL], &ctx.indent]), false);
    if ctx.actual_string && tag_test(&s) {
        return quoted(value, ctx);
    }
    if ctx.implicit_key {
        s
    } else {
        fold(&s, &ctx.indent, Mode::Flow, ctx.indent_at_start).0
    }
}

fn string_scalar(value: &[u16], ctx: &mut Ctx) -> U {
    let control = value.iter().any(|&c| matches!(c, 0..=8 | 0x0B..=0x1F | 0x7F..=0x9F));
    let lone = {
        let n = value.len();
        (0..n).any(|i| match value[i] {
            0xD800..=0xDBFF => !(i + 1 < n && (0xDC00..=0xDFFF).contains(&value[i + 1])),
            0xDC00..=0xDFFF => !(i > 0 && (0xD800..=0xDBFF).contains(&value[i - 1])),
            _ => false,
        })
    };
    if lone || control {
        double_quoted(value, ctx)
    } else {
        plain(value, ctx)
    }
}

fn number(f: f64) -> String {
    if !f.is_finite() {
        return if f.is_nan() {
            ".nan".into()
        } else if f < 0.0 {
            "-.inf".into()
        } else {
            ".inf".into()
        };
    }
    if f == 0.0 && f.is_sign_negative() {
        return "-0".into();
    }
    js_number_string(f)
}

// ---- nodes --------------------------------------------------------------------------------------------------------------------

fn item_ctx(ctx: &Ctx, indent: U) -> Ctx {
    let mut c = ctx.clone();
    c.indent = indent;
    c
}

fn block(ctx: &Ctx, lines: &[U], empty: &str) -> U {
    let Some(first) = lines.first() else { return u(empty) };
    let mut out = first.clone();
    for line in &lines[1..] {
        if line.is_empty() {
            out.push(NL);
        } else {
            out.push(NL);
            out.extend(&ctx.indent);
            out.extend(line);
        }
    }
    out
}

fn stringify_item(g: &Builder, item: &Item, ctx: &mut Ctx) -> Result<U, String> {
    let node = match item {
        Item::Alias(name) => {
            if !ctx.anchors.borrow().contains(name) {
                return Err(format!("Unresolved alias (the anchor must be set before the alias): {name}"));
            }
            return Ok(u(&if ctx.implicit_key { format!("*{name} ") } else { format!("*{name}") }));
        }
        Item::Node(i) => &g.arena[*i],
    };
    let mut props = U::new();
    if let Some(a) = &node.anchor {
        ctx.anchors.borrow_mut().insert(a.clone());
        props = u(&format!("&{a}"));
        ctx.indent_at_start = Some(ctx.indent_at_start.unwrap_or(0) + props.len() as i64 + 1);
    }
    let s = match &node.k {
        K::Str(v) => {
            let mut c = ctx.clone();
            c.actual_string = true;
            string_scalar(v, &mut c)
        }
        K::Null => u("null"),
        K::Bool(b) => u(if *b { "true" } else { "false" }),
        K::Num(f) => u(&number(*f)),
        K::Seq(items) => {
            let mut ictx = item_ctx(ctx, cat(&[&ctx.indent, &two_spaces()]));
            let mut lines = Vec::new();
            for x in items {
                lines.push(cat(&[&u("- "), &stringify_item(g, x, &mut ictx)?]));
            }
            block(ctx, &lines, "[]")
        }
        K::Map(pairs) => {
            let mut ictx = item_ctx(ctx, ctx.indent.clone());
            let mut lines = Vec::new();
            for (k, v) in pairs {
                lines.push(pair(g, k, v, &mut ictx)?);
            }
            block(ctx, &lines, "{}")
        }
    };
    if props.is_empty() {
        return Ok(s);
    }
    let scalar = !matches!(node.k, K::Seq(_) | K::Map(_));
    Ok(if scalar || matches!(s.first(), Some(&0x7B) | Some(&0x5B)) { cat(&[&props, &[SP], &s]) } else { cat(&[&props, &[NL], &ctx.indent, &s]) })
}

fn pair(g: &Builder, key: &[u16], value: &Item, ctx: &mut Ctx) -> Result<U, String> {
    let indent = ctx.indent.clone();
    let mut ctx = ctx.clone();
    ctx.implicit_key = true;
    ctx.indent = cat(&[&indent, &two_spaces()]);
    let mut kctx = ctx.clone();
    kctx.actual_string = true;
    let mut s = string_scalar(key, &mut kctx);
    let explicit = s.len() > 1024;
    s = if explicit { cat(&[&u("? "), &s, &[NL], &indent, &u(":")]) } else { cat(&[&s, &u(":")]) };
    ctx.implicit_key = false;
    let (is_scalar, coll_len) = match value {
        Item::Alias(_) => (false, None),
        Item::Node(i) => match &g.arena[*i].k {
            K::Seq(x) => (false, Some(x.len())),
            K::Map(x) => (false, Some(x.len())),
            _ => (true, None),
        },
    };
    if !explicit && is_scalar {
        ctx.indent_at_start = Some(s.len() as i64 + 1);
    }
    let vs = stringify_item(g, value, &mut ctx)?;
    let mut ws: U = vec![SP];
    if !explicit && coll_len.is_some() {
        let nl0 = vs.iter().position(|&c| c == NL);
        let flow = coll_len == Some(0);
        if nl0.is_some() || !flow {
            let mut props_line = false;
            if let Some(nl0) = nl0 {
                if vs[0] == ch('&') || vs[0] == ch('!') {
                    let mut sp0 = vs.iter().position(|&c| c == SP);
                    if vs[0] == ch('&') {
                        if let Some(p) = sp0 {
                            if p < nl0 && vs.get(p + 1) == Some(&ch('!')) {
                                sp0 = vs[p + 1..].iter().position(|&c| c == SP).map(|q| q + p + 1);
                            }
                        }
                    }
                    if sp0.is_none_or(|p| nl0 < p) {
                        props_line = true;
                    }
                }
            }
            if !props_line {
                ws = cat(&[&[NL], &ctx.indent]);
            }
        }
    } else if vs.is_empty() || vs[0] == NL {
        ws = U::new();
    }
    Ok(cat(&[&s, &ws, &vs]))
}

/// The YAML text of a graph of plain data, as UTF-16 code units (a JavaScript string; lone surrogates can only occur when the
/// reference's own fold splits a surrogate pair).
pub fn stringify_units(root: &Y) -> Result<Vec<u16>, String> {
    let mut b = Builder { arena: Vec::new(), seen: HashMap::new(), n: 0 };
    let item = b.node(root);
    b.finish();
    let mut ctx = Ctx {
        indent: U::new(),
        indent_at_start: None,
        implicit_key: false,
        actual_string: false,
        force_block_indent: false,
        anchors: Rc::new(RefCell::new(HashSet::new())),
    };
    let mut body = stringify_item(&b, &item, &mut ctx)?;
    body.push(NL);
    Ok(body)
}

/// The YAML text of plain data; repeated containers become anchors and aliases.
pub fn stringify_graph(root: &Y) -> Result<String, String> {
    String::from_utf16(&stringify_units(root)?).map_err(|_| "the YAML text splits a surrogate pair".to_string())
}

/// The YAML text of a JSON value.
pub fn stringify(v: &Value) -> Result<String, String> {
    stringify_graph(&Y::from_value(v))
}

/// `ns: <ns>` and `actions: [...]` as YAML over a graph (shared containers are anchored); a def whose verb has an own entry in `rules`
/// gets it re-attached as its `rules` member.
pub fn defs_to_yaml_units(ns: &[u16], defs: &[Y], rules: Option<&Y>) -> Result<Vec<u16>, String> {
    let rule_of = |d: &Y| -> Option<Y> {
        let (Y::Map(dm), Some(Y::Map(rm))) = (d, rules) else { return None };
        let verb = dm.borrow().iter().find(|(k, _)| k == &u("verb"))?.1.clone();
        let Y::Str(verb) = verb else { return None };
        let found = rm.borrow().iter().find(|(k, _)| *k == verb).map(|(_, v)| v.clone());
        found
    };
    let actions: Vec<Y> = defs
        .iter()
        .map(|d| match (d, rule_of(d)) {
            (Y::Map(dm), Some(r)) => {
                let mut pairs: Vec<(U, Y)> = dm.borrow().clone();
                match pairs.iter_mut().find(|(k, _)| *k == u("rules")) {
                    Some(slot) => slot.1 = r,
                    None => pairs.push((u("rules"), r)),
                }
                Y::map(pairs)
            }
            _ => d.clone(),
        })
        .collect();
    stringify_units(&Y::map(vec![(u("ns"), Y::Str(ns.to_vec())), (u("actions"), Y::seq(actions))]))
}

/// [`defs_to_yaml_units`] over JSON values.
pub fn defs_to_yaml(ns: &str, defs: &[Value], rules: Option<&Value>) -> Result<String, String> {
    let defs: Vec<Y> = defs.iter().map(Y::from_value).collect();
    let rules = rules.map(Y::from_value);
    let units = defs_to_yaml_units(&u(ns), &defs, rules.as_ref())?;
    String::from_utf16(&units).map_err(|_| "the YAML text splits a surrogate pair".to_string())
}
