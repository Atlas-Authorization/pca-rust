//! A matcher for the JavaScript regular expression dialect (ECMAScript, no flags, Annex B leniency) used by `path_re` of the suggestion
//! rules. It exists so a rule set is accepted or refused exactly as the reference's `new RegExp(...)` does and matches the same
//! locations, on UTF-16 code units. Syntax the reference rejects is an `Err`. Supported: literals, `.`, anchors, `\b \B`, classes with
//! ranges and class escapes, groups `(...)` and `(?:...)`, alternation, greedy and lazy quantifiers (laziness cannot change whether a
//! pattern matches somewhere, so only that is decided). Lookaround, named groups and back-references are refused (the rule validator
//! refuses them before a pattern is compiled). The match is a set simulation (no backtracking), so it runs in polynomial time.

use std::collections::BTreeSet;

type Iv = Vec<(u32, u32)>;
type PR<T> = Result<T, String>;

const WS: [(u32, u32); 10] = [
    (9, 13),
    (32, 32),
    (0xA0, 0xA0),
    (0x1680, 0x1680),
    (0x2000, 0x200A),
    (0x2028, 0x2029),
    (0x202F, 0x202F),
    (0x205F, 0x205F),
    (0x3000, 0x3000),
    (0xFEFF, 0xFEFF),
];
const DIGIT: [(u32, u32); 1] = [(48, 57)];
const WORD: [(u32, u32); 4] = [(48, 57), (65, 90), (95, 95), (97, 122)];
const MAX: u32 = 0xFFFF;
const END: u32 = u32::MAX;

fn norm(mut iv: Iv) -> Iv {
    iv.sort();
    let mut out: Iv = vec![];
    for (lo, hi) in iv {
        if let Some(l) = out.last_mut() {
            if lo <= l.1 + 1 {
                l.1 = l.1.max(hi);
                continue;
            }
        }
        out.push((lo, hi));
    }
    out
}

fn neg(iv: &[(u32, u32)]) -> Iv {
    let mut out: Iv = vec![];
    let mut cur = 0u32;
    for (lo, hi) in norm(iv.to_vec()) {
        if lo > cur {
            out.push((cur, lo - 1));
        }
        cur = hi + 1;
    }
    if cur <= MAX {
        out.push((cur, MAX));
    }
    out
}

/// The string as UTF-16 code units.
pub fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[derive(Debug, Clone)]
enum Node {
    Class(Iv),
    Cat(Vec<Node>),
    Alt(Vec<Node>),
    Rep(Box<Node>, u64, Option<u64>),
    Start,
    End,
    /// `\b` (true) or `\B` (false)
    Boundary(bool),
}

fn class_escape(c: u32) -> Option<Iv> {
    let base: &[(u32, u32)] = match c as u8 as char {
        'd' | 'D' if c < 128 => &DIGIT,
        'w' | 'W' if c < 128 => &WORD,
        's' | 'S' if c < 128 => &WS,
        _ => return None,
    };
    let upper = (c as u8 as char).is_ascii_uppercase();
    Some(if upper { neg(base) } else { norm(base.to_vec()) })
}

struct P {
    s: Vec<u16>,
    i: usize,
}

impl P {
    fn pk(&self, k: usize) -> u32 {
        self.s.get(self.i + k).map_or(END, |u| *u as u32)
    }
    fn is(&self, k: usize, c: char) -> bool {
        self.pk(k) == c as u32
    }
    fn err<T>(&self, msg: &str) -> PR<T> {
        Err(format!("Invalid regular expression: {msg}"))
    }

    fn disjunction(&mut self, depth: usize) -> PR<Node> {
        let mut alts = vec![self.alternative(depth)?];
        while self.is(0, '|') {
            self.i += 1;
            alts.push(self.alternative(depth)?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap_or(Node::Cat(vec![])) } else { Node::Alt(alts) })
    }

    fn alternative(&mut self, depth: usize) -> PR<Node> {
        let mut out: Vec<Node> = vec![];
        while self.i < self.s.len() && !self.is(0, '|') && !self.is(0, ')') {
            out.push(self.term(depth)?);
        }
        Ok(Node::Cat(out))
    }

    /// `{n}`, `{n,}` or `{n,m}` at the cursor: (min, max or None, length), or None when the brace is not a quantifier.
    fn braced(&self) -> PR<Option<(u64, Option<u64>, usize)>> {
        let digit = |j: usize| self.s.get(j).is_some_and(|u| (48..=57).contains(u));
        let num = |a: usize, b: usize| self.s[a..b].iter().fold(0u64, |n, u| n.saturating_mul(10).saturating_add((*u - 48) as u64));
        if !self.is(0, '{') {
            return Ok(None);
        }
        let mut j = self.i + 1;
        let st = j;
        while digit(j) {
            j += 1;
        }
        if j == st {
            return Ok(None);
        }
        let lo = num(st, j);
        let mut hi = Some(lo);
        if self.s.get(j) == Some(&(',' as u16)) {
            j += 1;
            let st2 = j;
            while digit(j) {
                j += 1;
            }
            hi = if j == st2 { None } else { Some(num(st2, j)) };
        }
        if self.s.get(j) != Some(&('}' as u16)) {
            return Ok(None);
        }
        j += 1;
        if let Some(h) = hi {
            if h < lo {
                return self.err("numbers out of order in {} quantifier");
            }
        }
        Ok(Some((lo, hi, j - self.i)))
    }

    fn quantifier(&mut self, atom: Node) -> PR<Node> {
        let (lo, hi) = if self.is(0, '*') {
            self.i += 1;
            (0, None)
        } else if self.is(0, '+') {
            self.i += 1;
            (1, None)
        } else if self.is(0, '?') {
            self.i += 1;
            (0, Some(1))
        } else {
            let b = if self.is(0, '{') { self.braced()? } else { None };
            match b {
                None => return Ok(atom),
                Some((lo, hi, n)) => {
                    self.i += n;
                    (lo, hi)
                }
            }
        };
        if self.is(0, '?') {
            self.i += 1;
        }
        Ok(Node::Rep(Box::new(atom), lo, hi))
    }

    fn term(&mut self, depth: usize) -> PR<Node> {
        if self.is(0, '^') {
            self.i += 1;
            return Ok(Node::Start);
        }
        if self.is(0, '$') {
            self.i += 1;
            return Ok(Node::End);
        }
        if self.is(0, '\\') && (self.is(1, 'b') || self.is(1, 'B')) {
            let b = self.is(1, 'b');
            self.i += 2;
            return Ok(Node::Boundary(b));
        }
        if self.is(0, '*') || self.is(0, '+') || self.is(0, '?') {
            return self.err("nothing to repeat");
        }
        if self.is(0, '{') && self.braced()?.is_some() {
            return self.err("nothing to repeat");
        }
        let a = self.atom(depth)?;
        self.quantifier(a)
    }

    fn atom(&mut self, depth: usize) -> PR<Node> {
        if depth > 200 {
            return self.err("too deeply nested");
        }
        if self.is(0, '(') {
            self.i += 1;
            if self.is(0, '?') {
                if !self.is(1, ':') {
                    return self.err("invalid group");
                }
                self.i += 2;
            }
            let body = self.disjunction(depth + 1)?;
            if !self.is(0, ')') {
                return self.err("unterminated group");
            }
            self.i += 1;
            return Ok(body);
        }
        if self.is(0, '.') {
            self.i += 1;
            return Ok(Node::Class(neg(&[(10, 10), (13, 13), (0x2028, 0x2029)])));
        }
        if self.is(0, '[') {
            return self.char_class();
        }
        if self.is(0, '\\') {
            return self.atom_escape();
        }
        let c = self.pk(0);
        self.i += 1;
        Ok(Node::Class(vec![(c, c)]))
    }

    fn hex(&mut self, n: usize) -> Option<u32> {
        let h = self.s.get(self.i..self.i + n)?;
        let mut v = 0u32;
        for u in h {
            v = v * 16 + char::from_u32(*u as u32)?.to_digit(16)?;
        }
        self.i += n;
        Some(v)
    }

    /// The code unit a character escape at `\` denotes (cursor past the escape).
    fn escape_char(&mut self, in_class: bool) -> PR<u32> {
        self.i += 1; // the backslash
        if self.i >= self.s.len() {
            return self.err("\\ at end of pattern");
        }
        let c = self.s[self.i] as u32;
        let ch = char::from_u32(c).unwrap_or('\u{0}');
        match ch {
            'f' | 'n' | 'r' | 't' | 'v' => {
                self.i += 1;
                return Ok(match ch {
                    'f' => 12,
                    'n' => 10,
                    'r' => 13,
                    't' => 9,
                    _ => 11,
                });
            }
            'c' => {
                let nxt = self.pk(1);
                let nc = char::from_u32(nxt).unwrap_or('\u{0}');
                if nxt != END && nc.is_ascii_alphabetic() {
                    self.i += 2;
                    return Ok(nxt % 32);
                }
                if in_class && nxt != END && (nc.is_ascii_digit() || nc == '_') {
                    self.i += 2;
                    return Ok(nxt % 32);
                }
                return Ok('\\' as u32); // a lone backslash; the `c` is read next
            }
            '0' => {
                self.i += 1;
                let mut v = 0u32;
                let mut n = 0;
                while n < 3 {
                    let d = char::from_u32(self.pk(0)).and_then(|x| x.to_digit(8));
                    match d {
                        Some(d) if self.pk(0) != END && v * 8 + d <= 0o377 => {
                            v = v * 8 + d;
                            self.i += 1;
                            n += 1;
                        }
                        _ => break,
                    }
                }
                return Ok(v);
            }
            'x' => {
                self.i += 1;
                return Ok(self.hex(2).unwrap_or('x' as u32));
            }
            'u' => {
                self.i += 1;
                return Ok(self.hex(4).unwrap_or('u' as u32));
            }
            'b' if in_class => {
                self.i += 1;
                return Ok(8);
            }
            '1'..='9' => return self.err("back-references are not supported"),
            _ => {}
        }
        self.i += 1;
        Ok(c)
    }

    fn atom_escape(&mut self) -> PR<Node> {
        let c = self.pk(1);
        if let Some(iv) = class_escape(c) {
            self.i += 2;
            return Ok(Node::Class(iv));
        }
        let u = self.escape_char(false)?;
        Ok(Node::Class(vec![(u, u)]))
    }

    /// (code unit, interval set): exactly one of the two is present.
    fn class_atom(&mut self) -> PR<(u32, Option<Iv>)> {
        if self.is(0, '\\') {
            if let Some(iv) = class_escape(self.pk(1)) {
                self.i += 2;
                return Ok((0, Some(iv)));
            }
            return Ok((self.escape_char(true)?, None));
        }
        let c = self.pk(0);
        self.i += 1;
        Ok((c, None))
    }

    fn char_class(&mut self) -> PR<Node> {
        self.i += 1;
        let mut negate = false;
        if self.is(0, '^') {
            negate = true;
            self.i += 1;
        }
        let mut iv: Iv = vec![];
        loop {
            if self.i >= self.s.len() {
                return self.err("unterminated character class");
            }
            if self.is(0, ']') {
                self.i += 1;
                break;
            }
            let (a, aset) = self.class_atom()?;
            if self.is(0, '-') && !self.is(1, ']') && self.pk(1) != END {
                self.i += 1;
                let (b, bset) = self.class_atom()?;
                if aset.is_some() || bset.is_some() {
                    // Annex B: a class escape on either side makes the dash a literal
                    iv.extend(aset.unwrap_or_else(|| vec![(a, a)]));
                    iv.push((45, 45));
                    iv.extend(bset.unwrap_or_else(|| vec![(b, b)]));
                    continue;
                }
                if a > b {
                    return self.err("range out of order in character class");
                }
                iv.push((a, b));
                continue;
            }
            iv.extend(aset.unwrap_or_else(|| vec![(a, a)]));
        }
        Ok(Node::Class(if negate { neg(&iv) } else { norm(iv) }))
    }
}

fn is_word(s: &[u16], p: usize) -> bool {
    s.get(p).is_some_and(|u| WORD.iter().any(|(lo, hi)| (*lo..=*hi).contains(&(*u as u32))))
}

/// The end positions reachable from any of the start positions through `node`.
fn step(node: &Node, s: &[u16], set: &BTreeSet<usize>) -> BTreeSet<usize> {
    match node {
        Node::Class(iv) => {
            set.iter().filter(|p| s.get(**p).is_some_and(|u| iv.iter().any(|(lo, hi)| (*lo..=*hi).contains(&(*u as u32))))).map(|p| p + 1).collect()
        }
        Node::Cat(xs) => {
            let mut cur = set.clone();
            for x in xs {
                if cur.is_empty() {
                    break;
                }
                cur = step(x, s, &cur);
            }
            cur
        }
        Node::Alt(xs) => {
            let mut out = BTreeSet::new();
            for x in xs {
                out.extend(step(x, s, set));
            }
            out
        }
        Node::Start => set.iter().filter(|p| **p == 0).cloned().collect(),
        Node::End => set.iter().filter(|p| **p == s.len()).cloned().collect(),
        Node::Boundary(want) => set.iter().filter(|p| ((**p > 0 && is_word(s, **p - 1)) != is_word(s, **p)) == *want).cloned().collect(),
        Node::Rep(inner, min, max) => {
            let mut cur = set.clone();
            let mut k = 0u64;
            while k < *min {
                let next = step(inner, s, &cur);
                if next == cur {
                    break; // a fixed point stays fixed, so the minimum is met
                }
                cur = next;
                k += 1;
                if cur.is_empty() {
                    return cur;
                }
            }
            let mut acc = cur.clone();
            let mut frontier = cur;
            let mut j = *min;
            while max.map_or(true, |m| j < m) {
                let next = step(inner, s, &frontier);
                let fresh: BTreeSet<usize> = next.difference(&acc).cloned().collect();
                if fresh.is_empty() {
                    break;
                }
                acc.extend(fresh.iter().cloned());
                frontier = fresh;
                j += 1;
            }
            acc
        }
    }
}

/// A compiled pattern.
#[derive(Debug, Clone)]
pub struct JsRe {
    root: Node,
}

/// Compile a JavaScript pattern, or the reason it is not one.
pub fn compile_js(pattern: &str) -> Result<JsRe, String> {
    let mut p = P { s: to_utf16(pattern), i: 0 };
    let root = p.disjunction(0)?;
    if p.i < p.s.len() {
        return p.err("unmatched ')'");
    }
    Ok(JsRe { root })
}

/// `RegExp.prototype.test`: a match anywhere in the string (as UTF-16 code units).
pub fn js_test(rx: &JsRe, s: &str) -> bool {
    let u = to_utf16(s);
    let start: BTreeSet<usize> = (0..=u.len()).collect();
    !step(&rx.root, &u, &start).is_empty()
}
