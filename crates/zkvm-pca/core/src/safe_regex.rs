//! R4-02: a line-by-line port of the TypeScript linear-time `re:` matcher so the guest and the TS verifier
//! evaluate the SAME patterns with the SAME semantics.
//!
//! Ports, in order:
//!   * `packages/pca/src/predicates.ts` `isSafeRegexSource` (the structural guard: no backreferences, no
//!     lookaround, no quantified group that holds a quantifier or an alternation, at most 3 unbounded
//!     quantifiers, repeat bounds <= 64, a 22-bit backtracking-cost budget), and
//!   * `packages/pca/src/safe-regex.ts` (the parser, the Thompson NFA compiler and the Pike simulation, a
//!     JavaScript flagless `RegExp` subset over UTF-16 code units).
//!
//! A pattern is evaluated only when BOTH accept it; anything else is REFUSED (the predicate does not match).
//! Matching is over UTF-16 code units (so `.` matches half of an astral character, `\d \w \s` are the ASCII /
//! JavaScript sets, `.` excludes `\n \r U+2028 U+2029`, there are no flags, no `\b`, no `\p`). The `regex` crate is
//! NOT used any more: its Unicode-aware semantics differed from the reference on 15 of 17 audited cases.
//!
//! Resource limits are identical to the TS: pattern <= 4096 NFA instructions, `{n,m}` bounds <= 64, and the
//! matcher refuses (returns `None`) when `instructions x (subject length + 1)` exceeds 2,000,000.
//! One deliberate fail-closed difference: the parser nests at most [`MAX_PARSE_DEPTH`] groups deep (the TS relies on
//! its stack and refuses on a `RangeError`); a 200-code-unit source cannot reach that depth legitimately, so the
//! limit is only ever hit by an adversarial pattern, which both sides refuse.

/// Largest NFA (instruction count) a pattern may compile to.
pub const MAX_NFA_INSTRUCTIONS: usize = 4096;
/// Largest `{n,m}` bound.
pub const MAX_REPEAT: u64 = 64;
/// Hard cap on (NFA size x (subject length + 1)).
pub const MAX_MATCH_STEPS: usize = 2_000_000;
/// Parser recursion limit (groups / nested emit), fail closed beyond it.
pub const MAX_PARSE_DEPTH: usize = 256;

const MAX_UNBOUNDED_QUANTIFIERS: u32 = 3;
const MAX_BOUNDED_REPEAT: u64 = 64;
const MAX_REGEX_COST_BITS: u32 = 22;
const UNBOUNDED_QUANTIFIER_BITS: u32 = 8;

type Ranges = Vec<(u32, u32)>;

const DIGIT: [(u32, u32); 1] = [(0x30, 0x39)];
const WORD: [(u32, u32); 4] = [(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)];
const SPACE: [(u32, u32); 10] = [
    (0x09, 0x0d),
    (0x20, 0x20),
    (0xa0, 0xa0),
    (0x1680, 0x1680),
    (0x2000, 0x200a),
    (0x2028, 0x2029),
    (0x202f, 0x202f),
    (0x205f, 0x205f),
    (0x3000, 0x3000),
    (0xfeff, 0xfeff),
];
const LINE_TERMINATORS: [(u32, u32); 3] = [(0x0a, 0x0a), (0x0d, 0x0d), (0x2028, 0x2029)];

#[derive(Clone, Debug)]
struct CharSet {
    ranges: Ranges,
    negated: bool,
}

impl CharSet {
    fn new(r: &[(u32, u32)], negated: bool) -> Self {
        CharSet { ranges: r.to_vec(), negated }
    }
    fn single(c: u32) -> Self {
        CharSet { ranges: vec![(c, c)], negated: false }
    }
    fn has(&self, c: u32) -> bool {
        let mut inside = false;
        let (mut lo, mut hi) = (0i64, self.ranges.len() as i64 - 1);
        while lo <= hi {
            let mid = (lo + hi) >> 1;
            let r = self.ranges[mid as usize];
            if c < r.0 {
                hi = mid - 1;
            } else if c > r.1 {
                lo = mid + 1;
            } else {
                inside = true;
                break;
            }
        }
        inside != self.negated
    }
}

fn normalize(ranges: &[(u32, u32)]) -> Ranges {
    let mut s = ranges.to_vec();
    s.sort_by_key(|r| r.0);
    let mut out: Ranges = Vec::new();
    for r in s {
        match out.last_mut() {
            Some(last) if r.0 <= last.1 + 1 => last.1 = last.1.max(r.1),
            _ => out.push(r),
        }
    }
    out
}

fn complement(r: &[(u32, u32)]) -> Ranges {
    let mut out = Vec::new();
    let mut next: u32 = 0;
    for (a, b) in normalize(r) {
        if a > next {
            out.push((next, a - 1));
        }
        next = b + 1;
    }
    if next <= 0xffff {
        out.push((next, 0xffff));
    }
    out
}

enum Node {
    Set(CharSet),
    Bol,
    Eol,
    Cat(Vec<Node>),
    Alt(Vec<Node>),
    /// `max == None` is unbounded.
    Rep { node: Box<Node>, min: u64, max: Option<u64> },
}

struct Refuse;
type R<T> = Result<T, Refuse>;

struct Parser<'a> {
    s: &'a [u16],
    i: usize,
    depth: usize,
}

fn is_ascii_alnum(c: u16) -> bool {
    (0x30..=0x39).contains(&c) || (0x41..=0x5a).contains(&c) || (0x61..=0x7a).contains(&c)
}
fn is_hex(c: u16) -> bool {
    (0x30..=0x39).contains(&c) || (0x41..=0x46).contains(&c) || (0x61..=0x66).contains(&c)
}
fn is_digit(c: u16) -> bool {
    (0x30..=0x39).contains(&c)
}
fn hexval(c: u16) -> u32 {
    match c {
        0x30..=0x39 => (c - 0x30) as u32,
        0x41..=0x46 => (c - 0x41 + 10) as u32,
        _ => (c - 0x61 + 10) as u32,
    }
}

impl<'a> Parser<'a> {
    fn at(&self, k: usize) -> Option<u16> {
        self.s.get(k).copied()
    }

    fn parse(&mut self) -> R<Node> {
        let n = self.alt()?;
        if self.i < self.s.len() {
            return Err(Refuse); // unbalanced )
        }
        Ok(n)
    }

    fn alt(&mut self) -> R<Node> {
        let mut items = vec![self.cat()?];
        while self.at(self.i) == Some(b'|' as u16) {
            self.i += 1;
            items.push(self.cat()?);
        }
        if items.len() == 1 {
            Ok(items.pop().unwrap())
        } else {
            Ok(Node::Alt(items))
        }
    }

    fn cat(&mut self) -> R<Node> {
        let mut items = Vec::new();
        while let Some(c) = self.at(self.i) {
            if c == b'|' as u16 || c == b')' as u16 {
                break;
            }
            items.push(self.quantified()?);
        }
        Ok(Node::Cat(items))
    }

    /// Reads `{n}` `{n,}` `{n,m}` (1..4 digits each) at `self.i`; None when not a well-formed quantifier.
    fn brace_quantifier(&self) -> Option<(u64, Option<u64>, usize)> {
        let mut k = self.i + 1;
        let d0 = k;
        while k < self.s.len() && k - d0 < 4 && is_digit(self.s[k]) {
            k += 1;
        }
        if k == d0 {
            return None;
        }
        let num = |a: usize, b: usize| self.s[a..b].iter().fold(0u64, |acc, &c| acc * 10 + (c - 0x30) as u64);
        let min = num(d0, k);
        let max;
        if self.at(k) == Some(b',' as u16) {
            k += 1;
            let m0 = k;
            while k < self.s.len() && k - m0 < 4 && is_digit(self.s[k]) {
                k += 1;
            }
            max = if k == m0 { None } else { Some(num(m0, k)) };
        } else {
            max = Some(min);
        }
        if self.at(k) != Some(b'}' as u16) {
            return None;
        }
        Some((min, max, k + 1 - self.i))
    }

    fn quantified(&mut self) -> R<Node> {
        let atom = self.atom()?;
        let (min, max): (u64, Option<u64>);
        match self.at(self.i) {
            Some(0x2a) => {
                min = 0;
                max = None;
                self.i += 1;
            }
            Some(0x2b) => {
                min = 1;
                max = None;
                self.i += 1;
            }
            Some(0x3f) => {
                min = 0;
                max = Some(1);
                self.i += 1;
            }
            Some(0x7b) => {
                let (lo, hi, len) = self.brace_quantifier().ok_or(Refuse)?;
                if let Some(h) = hi {
                    if h < lo {
                        return Err(Refuse);
                    }
                }
                min = lo;
                max = hi;
                self.i += len;
            }
            _ => return Ok(atom),
        }
        if matches!(atom, Node::Bol | Node::Eol) {
            return Err(Refuse);
        }
        if matches!(max, Some(m) if m > MAX_REPEAT) || min > MAX_REPEAT {
            return Err(Refuse);
        }
        if self.at(self.i) == Some(0x3f) {
            self.i += 1; // lazy: irrelevant to a full-match boolean
        }
        Ok(Node::Rep { node: Box::new(atom), min, max })
    }

    fn atom(&mut self) -> R<Node> {
        let c = self.at(self.i).ok_or(Refuse)?;
        match c {
            0x28 => {
                // (
                self.i += 1;
                if self.at(self.i) == Some(0x3f) {
                    if self.at(self.i + 1) != Some(0x3a) {
                        return Err(Refuse);
                    }
                    self.i += 2;
                }
                self.depth += 1;
                if self.depth > MAX_PARSE_DEPTH {
                    return Err(Refuse);
                }
                let n = self.alt()?;
                self.depth -= 1;
                if self.at(self.i) != Some(0x29) {
                    return Err(Refuse);
                }
                self.i += 1;
                Ok(n)
            }
            0x5b => self.cls(),
            0x2e => {
                self.i += 1;
                Ok(Node::Set(CharSet::new(&LINE_TERMINATORS, true)))
            }
            0x5e => {
                self.i += 1;
                Ok(Node::Bol)
            }
            0x24 => {
                self.i += 1;
                Ok(Node::Eol)
            }
            0x5c => {
                let e = self.escape_inner(false)?;
                Ok(Node::Set(e.0))
            }
            0x2a | 0x2b | 0x3f | 0x7b => Err(Refuse),
            _ => {
                self.i += 1;
                Ok(Node::Set(CharSet::single(c as u32)))
            }
        }
    }

    /// After `\`: (set, is_class_escape, single char code).
    fn escape_inner(&mut self, in_class: bool) -> R<(CharSet, bool, Option<u32>)> {
        self.i += 1; // backslash
        let c = self.at(self.i).ok_or(Refuse)?;
        self.i += 1;
        let single = |code: u32| Ok((CharSet::single(code), false, Some(code)));
        match c {
            0x64 => Ok((CharSet::new(&DIGIT, false), true, None)),
            0x44 => Ok((CharSet::new(&DIGIT, true), true, None)),
            0x77 => Ok((CharSet::new(&WORD, false), true, None)),
            0x57 => Ok((CharSet::new(&WORD, true), true, None)),
            0x73 => Ok((CharSet::new(&SPACE, false), true, None)),
            0x53 => Ok((CharSet::new(&SPACE, true), true, None)),
            0x74 => single(9),
            0x6e => single(10),
            0x76 => single(11),
            0x66 => single(12),
            0x72 => single(13),
            0x30 => {
                if matches!(self.at(self.i), Some(d) if is_digit(d)) {
                    return Err(Refuse); // octal escape
                }
                single(0)
            }
            0x78 => {
                if let (Some(a), Some(b)) = (self.at(self.i), self.at(self.i + 1)) {
                    if is_hex(a) && is_hex(b) {
                        self.i += 2;
                        return single(hexval(a) * 16 + hexval(b));
                    }
                }
                Err(Refuse)
            }
            0x75 => {
                let mut v = 0u32;
                for k in 0..4 {
                    match self.at(self.i + k) {
                        Some(h) if is_hex(h) => v = v * 16 + hexval(h),
                        _ => return Err(Refuse),
                    }
                }
                self.i += 4;
                single(v)
            }
            0x63 => match self.at(self.i) {
                Some(l) if (0x41..=0x5a).contains(&l) || (0x61..=0x7a).contains(&l) => {
                    self.i += 1;
                    single((l as u32) % 32)
                }
                _ => Err(Refuse),
            },
            0x62 => {
                if in_class {
                    single(8)
                } else {
                    Err(Refuse)
                }
            }
            _ => {
                if is_ascii_alnum(c) || c == 0x5f {
                    return Err(Refuse);
                }
                single(c as u32)
            }
        }
    }

    fn cls(&mut self) -> R<Node> {
        self.i += 1; // [
        let mut negated = false;
        if self.at(self.i) == Some(0x5e) {
            negated = true;
            self.i += 1;
        }
        let mut ranges: Ranges = Vec::new();
        // (ranges, ch, is_class_escape)
        fn read_atom(p: &mut Parser) -> R<(Ranges, Option<u32>, bool)> {
            let c = p.at(p.i).ok_or(Refuse)?;
            if c == 0x5c {
                let (set, cls, ch) = p.escape_inner(true)?;
                let rs = if set.negated { complement(&set.ranges) } else { set.ranges.clone() };
                return Ok((rs, ch, cls));
            }
            p.i += 1;
            Ok((vec![(c as u32, c as u32)], Some(c as u32), false))
        }
        loop {
            let c = self.at(self.i).ok_or(Refuse)?;
            if c == 0x5d {
                self.i += 1;
                break;
            }
            let a = read_atom(self)?;
            let dash = self.at(self.i) == Some(0x2d);
            let after = self.at(self.i + 1);
            if dash && after.is_some() && after != Some(0x5d) {
                self.i += 1;
                let b = read_atom(self)?;
                if a.2 || b.2 {
                    // Annex B: a class escape as a range endpoint makes the '-' a literal
                    ranges.extend(a.0.iter().copied());
                    ranges.push((0x2d, 0x2d));
                    ranges.extend(b.0.iter().copied());
                } else {
                    let (x, y) = (a.1.ok_or(Refuse)?, b.1.ok_or(Refuse)?);
                    if x > y {
                        return Err(Refuse);
                    }
                    ranges.push((x, y));
                }
            } else {
                ranges.extend(a.0.iter().copied());
            }
        }
        Ok(Node::Set(CharSet { ranges: normalize(&ranges), negated }))
    }
}

#[derive(Clone, Debug)]
enum Inst {
    Set(CharSet),
    Split(usize, usize),
    Jmp(usize),
    Bol,
    Eol,
    Match,
}

fn emit(node: &Node, prog: &mut Vec<Inst>, depth: usize) -> R<()> {
    if prog.len() > MAX_NFA_INSTRUCTIONS || depth > MAX_PARSE_DEPTH * 2 {
        return Err(Refuse);
    }
    match node {
        Node::Set(s) => prog.push(Inst::Set(s.clone())),
        Node::Bol => prog.push(Inst::Bol),
        Node::Eol => prog.push(Inst::Eol),
        Node::Cat(items) => {
            for it in items {
                emit(it, prog, depth + 1)?;
            }
        }
        Node::Alt(items) => {
            let mut jmps = Vec::new();
            for (i, it) in items.iter().enumerate() {
                if i < items.len() - 1 {
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, usize::MAX));
                    emit(it, prog, depth + 1)?;
                    jmps.push(prog.len());
                    prog.push(Inst::Jmp(usize::MAX));
                    let end = prog.len();
                    prog[split] = Inst::Split(split + 1, end);
                } else {
                    emit(it, prog, depth + 1)?;
                }
            }
            let end = prog.len();
            for j in jmps {
                prog[j] = Inst::Jmp(end);
            }
        }
        Node::Rep { node, min, max } => {
            for _ in 0..*min {
                emit(node, prog, depth + 1)?;
            }
            match max {
                None => {
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, usize::MAX));
                    emit(node, prog, depth + 1)?;
                    prog.push(Inst::Jmp(split));
                    let end = prog.len();
                    prog[split] = Inst::Split(split + 1, end);
                }
                Some(mx) => {
                    let mut splits = Vec::new();
                    for _ in *min..*mx {
                        splits.push(prog.len());
                        let at = prog.len();
                        prog.push(Inst::Split(at + 1, usize::MAX));
                        emit(node, prog, depth + 1)?;
                    }
                    let end = prog.len();
                    for sp in splits {
                        prog[sp] = Inst::Split(sp + 1, end);
                    }
                }
            }
            if prog.len() > MAX_NFA_INSTRUCTIONS {
                return Err(Refuse);
            }
        }
    }
    Ok(())
}

/// A compiled pattern.
pub struct Compiled {
    prog: Vec<Inst>,
}

/// `compileSafeRegex`: the NFA, or `None` when the source is outside the subset or too large. Never panics.
pub fn compile(src: &[u16]) -> Option<Compiled> {
    let mut p = Parser { s: src, i: 0, depth: 0 };
    let ast = p.parse().ok()?;
    let mut prog = Vec::new();
    emit(&ast, &mut prog, 0).ok()?;
    prog.push(Inst::Match);
    if prog.len() > MAX_NFA_INSTRUCTIONS {
        return None;
    }
    Some(Compiled { prog })
}

/// `runSafeRegex`: full match, `None` when the work budget would be exceeded.
pub fn run(re: &Compiled, subject: &[u16]) -> Option<bool> {
    let prog = &re.prog;
    let n = subject.len();
    if prog.len().checked_mul(n + 1)? > MAX_MATCH_STEPS {
        return None;
    }
    let mut mark = vec![usize::MAX; prog.len()];
    let mut epoch = 0usize;
    let mut matched = false;
    let mut stack: Vec<usize> = Vec::with_capacity(prog.len() * 2 + 2);

    let add = |list: &mut Vec<usize>, pc0: usize, pos: usize, mark: &mut Vec<usize>, epoch: usize, matched: &mut bool, stack: &mut Vec<usize>| {
        stack.clear();
        stack.push(pc0);
        while let Some(pc) = stack.pop() {
            if mark[pc] == epoch {
                continue;
            }
            mark[pc] = epoch;
            match &prog[pc] {
                Inst::Jmp(x) => stack.push(*x),
                Inst::Split(x, y) => {
                    stack.push(*y);
                    stack.push(*x);
                }
                Inst::Bol => {
                    if pos == 0 {
                        stack.push(pc + 1);
                    }
                }
                Inst::Eol => {
                    if pos == n {
                        stack.push(pc + 1);
                    }
                }
                Inst::Match => {
                    if pos == n {
                        *matched = true;
                    }
                }
                Inst::Set(_) => list.push(pc),
            }
        }
    };

    let mut clist: Vec<usize> = Vec::with_capacity(prog.len());
    let mut nlist: Vec<usize> = Vec::with_capacity(prog.len());
    epoch += 1;
    add(&mut clist, 0, 0, &mut mark, epoch, &mut matched, &mut stack);
    for pos in 0..n {
        let c = subject[pos] as u32;
        epoch += 1;
        nlist.clear();
        for k in 0..clist.len() {
            let pc = clist[k];
            if let Inst::Set(set) = &prog[pc] {
                if set.has(c) {
                    add(&mut nlist, pc + 1, pos + 1, &mut mark, epoch, &mut matched, &mut stack);
                }
            }
        }
        core::mem::swap(&mut clist, &mut nlist);
        if clist.is_empty() && !matched {
            return Some(false);
        }
    }
    Some(matched)
}

/// `isSafeRegexSource` (predicates.ts): the structural guard, ALSO requiring that the source compiles.
pub fn is_safe_regex_source(src: &[u16]) -> bool {
    #[derive(Clone, Copy)]
    struct Frame {
        has_quant: bool,
        has_alt: bool,
    }
    #[derive(Clone, Copy)]
    enum Prev {
        None,
        Atom,
        Group(Frame),
    }
    let mut stack = vec![Frame { has_quant: false, has_alt: false }];
    let mut prev = Prev::None;
    let mut unbounded = 0u32;
    let mut bits = 0u32;
    let mut i = 0usize;
    let len = src.len();
    while i < len {
        let ch = src[i];
        if ch == 0x5c {
            let n = match src.get(i + 1) {
                Some(&n) => n,
                None => return false,
            };
            if (0x31..=0x39).contains(&n) || n == 0x6b {
                return false; // backreference
            }
            i += 2;
            prev = Prev::Atom;
            continue;
        }
        if ch == 0x5b {
            let mut j = i + 1;
            if src.get(j) == Some(&0x5e) {
                j += 1;
            }
            while j < len && src[j] != 0x5d {
                if src[j] == 0x5c {
                    j += 1;
                }
                j += 1;
            }
            if j >= len {
                return false;
            }
            i = j + 1;
            prev = Prev::Atom;
            continue;
        }
        if ch == 0x28 {
            if src.get(i + 1) == Some(&0x3f) {
                if src.get(i + 2) != Some(&0x3a) {
                    return false;
                }
                i += 3;
            } else {
                i += 1;
            }
            stack.push(Frame { has_quant: false, has_alt: false });
            prev = Prev::None;
            continue;
        }
        if ch == 0x29 {
            if stack.len() < 2 {
                return false;
            }
            let f = stack.pop().unwrap();
            let parent = stack.last_mut().unwrap();
            parent.has_quant |= f.has_quant;
            parent.has_alt |= f.has_alt;
            prev = Prev::Group(f);
            i += 1;
            continue;
        }
        if ch == 0x7c {
            bits += 1;
            if bits > MAX_REGEX_COST_BITS {
                return false;
            }
            stack.last_mut().unwrap().has_alt = true;
            prev = Prev::None;
            i += 1;
            continue;
        }
        // quantifier: (len, unbounded, max (None = Infinity), options (None = Infinity))
        let mut q: Option<(usize, bool, Option<u64>, Option<u64>)> = None;
        if ch == 0x2a || ch == 0x2b {
            q = Some((1, true, None, None));
        } else if ch == 0x3f {
            q = Some((1, false, Some(1), Some(2)));
        } else if ch == 0x7b {
            // /^\{(\d+)(?:(,)(\d*))?\}/ on the whole remaining source
            let sat = |a: usize, b: usize| src[a..b].iter().fold(0u64, |acc, &c| acc.saturating_mul(10).saturating_add((c - 0x30) as u64));
            let mut k = i + 1;
            let d0 = k;
            while k < len && is_digit(src[k]) {
                k += 1;
            }
            if k == d0 {
                return false;
            }
            let lo = sat(d0, k);
            let hi: Option<u64>;
            if src.get(k) == Some(&0x2c) {
                k += 1;
                let m0 = k;
                while k < len && is_digit(src[k]) {
                    k += 1;
                }
                hi = if k == m0 { None } else { Some(sat(m0, k)) };
            } else {
                hi = Some(lo);
            }
            if src.get(k) != Some(&0x7d) {
                return false;
            }
            if let Some(h) = hi {
                if h < lo {
                    return false;
                }
            }
            q = Some((k + 1 - i, hi.is_none(), hi, hi.map(|h| h - lo + 1)));
        }
        if let Some((qlen, qunb, qmax, qopts)) = q {
            match prev {
                Prev::None => return false,
                Prev::Group(f) if f.has_quant || f.has_alt => return false,
                _ => {}
            }
            if qunb {
                unbounded += 1;
                if unbounded > MAX_UNBOUNDED_QUANTIFIERS {
                    return false;
                }
            }
            if !qunb {
                if let Some(m) = qmax {
                    if m > MAX_BOUNDED_REPEAT {
                        return false;
                    }
                }
            }
            bits += if qunb {
                UNBOUNDED_QUANTIFIER_BITS
            } else {
                match qopts {
                    Some(o) if o > 1 => 64 - (o - 1).leading_zeros(), // ceil(log2(o))
                    _ => 0,
                }
            };
            if bits > MAX_REGEX_COST_BITS {
                return false;
            }
            stack.last_mut().unwrap().has_quant = true;
            i += qlen;
            if src.get(i) == Some(&0x3f) {
                i += 1;
            }
            prev = Prev::None;
            continue;
        }
        i += 1;
        prev = Prev::Atom;
    }
    stack.len() == 1 && compile(src).is_some()
}

// ---- R4-05 mirror: the per-DOCUMENT regex work budget (packages/pca/src/regex-budget.ts) --------------------------------
//
// The TS reference caps, per scope (`decide`, `evaluatePredicates`, `evaluateCaveats`, `predicateMatches`,
// `evaluateConditionTri`), the number of regex evaluations, the total pattern source length and the summed worst-case
// NFA steps; once ANY cap would be exceeded the scope is poisoned and every later regex evaluation is refused (no match).
// The guest mirrors it so that it never ALLOWS a document the TS reference denies for exceeding the budget.

/// `MAX_REGEX_EVALUATIONS_PER_DOCUMENT`.
pub const MAX_REGEX_EVALUATIONS_PER_DOCUMENT: u64 = 64;
/// `MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT` (UTF-16 code units).
pub const MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT: u64 = 8192;
/// `MAX_REGEX_STEPS_PER_DOCUMENT`.
pub const MAX_REGEX_STEPS_PER_DOCUMENT: u64 = 5_000_000;

#[derive(Default)]
struct Budget {
    evaluations: u64,
    chars: u64,
    steps: u64,
}

thread_local! {
    static BUDGET: core::cell::RefCell<Option<Budget>> = const { core::cell::RefCell::new(None) };
}

/// `withRegexBudget`: run `f` inside a budget scope (joins the enclosing scope when one is open).
pub fn with_regex_budget<T>(f: impl FnOnce() -> T) -> T {
    let opened = BUDGET.with(|b| {
        let mut b = b.borrow_mut();
        if b.is_none() {
            *b = Some(Budget::default());
            true
        } else {
            false
        }
    });
    struct Close(bool);
    impl Drop for Close {
        fn drop(&mut self) {
            if self.0 {
                BUDGET.with(|b| *b.borrow_mut() = None);
            }
        }
    }
    let _close = Close(opened);
    f()
}

/// `chargeRegex`: false when this evaluation would exceed the document budget (the caller must NOT run the match).
/// Outside any scope: unbudgeted.
fn charge(src_units: u64, prog_len: u64, subject_units: u64) -> bool {
    BUDGET.with(|b| {
        let mut b = b.borrow_mut();
        let b = match b.as_mut() {
            Some(b) => b,
            None => return true,
        };
        let ev = b.evaluations + 1;
        let chars = b.chars + src_units;
        let steps = b.steps + prog_len * (subject_units + 1);
        if ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT || chars > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT || steps > MAX_REGEX_STEPS_PER_DOCUMENT {
            // poison the scope so a later, cheaper pattern cannot sneak in after an over-budget one
            b.evaluations = MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1;
            return false;
        }
        b.evaluations = ev;
        b.chars = chars;
        b.steps = steps;
        true
    })
}

/// `src` (WITHOUT the `re:` prefix) against `subject`, exactly as the TS reference does in `resourceMatches`:
/// `isSafeRegexSource(src)`, then `chargeRegex(src, subject.length)`, then `safeRegexFullMatch(src, subject) === true`.
/// Fails closed.
pub fn full_match(src: &str, subject: &str) -> bool {
    full_match_tri(src, subject) == Some(true)
}

/// Three-valued form for the `matches` condition (predicates.ts `triLeaf`): `None` = unknown (unsafe source, does not
/// compile, over the document budget, or the engine gave up), `Some(b)` = a clean verdict.
pub fn full_match_tri(src: &str, subject: &str) -> Option<bool> {
    let s: Vec<u16> = src.encode_utf16().collect();
    if !is_safe_regex_source(&s) {
        return None;
    }
    let re = compile(&s)?;
    let subj: Vec<u16> = subject.encode_utf16().collect();
    if !charge(s.len() as u64, re.prog.len() as u64, subj.len() as u64) {
        return None;
    }
    run(&re, &subj)
}
