//! Token tapes: the lossless card of a goal (`Render`/`Parse`, G-T10), the decoders of the non-goal inputs (ontology, action,
//! history) and the encoder of the compiled policy. Hand port of `formal/dafny/GoalRender.dfy` and the decoders / encoders of
//! `Goal.dfy`. A tape is a sequence of keywords, exact integers and exact strings; every decoder fails closed (`None`).
use super::compile::*;
use super::ir::*;
use std::collections::HashMap;
use std::fmt::Write;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    Kw(i64),
    I(i64),
    S(String),
}

/// A tape in the harness text syntax: `kN` keyword, `iN` integer, `s<hex>.<hex>` string as code points (bare `s` is empty).
pub fn tape_to_text(t: &[Tok]) -> String {
    let mut out = String::new();
    for (i, x) in t.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        match x {
            Tok::Kw(k) => {
                let _ = write!(out, "k{k}");
            }
            Tok::I(n) => {
                let _ = write!(out, "i{n}");
            }
            Tok::S(s) => {
                out.push('s');
                for (j, c) in s.chars().enumerate() {
                    if j > 0 {
                        out.push('.');
                    }
                    let _ = write!(out, "{:x}", c as u32);
                }
            }
        }
    }
    out
}
pub fn tape_from_text(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    for w in s.split(' ').filter(|w| !w.is_empty()) {
        let body = w.get(1..).unwrap_or("");
        match w.as_bytes()[0] {
            b'k' => out.push(Tok::Kw(body.parse::<i64>().map_err(|e| format!("bad keyword {w}: {e}"))?)),
            b'i' => out.push(Tok::I(body.parse::<i64>().map_err(|e| format!("bad integer {w}: {e}"))?)),
            b's' => {
                let mut st = String::new();
                if !body.is_empty() {
                    for h in body.split('.') {
                        let cp = u32::from_str_radix(h, 16).map_err(|e| format!("bad code point {h}: {e}"))?;
                        st.push(char::from_u32(cp).ok_or_else(|| format!("code point {cp:x} is not a Unicode scalar"))?);
                    }
                }
                out.push(Tok::S(st));
            }
            _ => return Err(format!("bad token {w}")),
        }
    }
    Ok(out)
}

// ---- encoding
fn kw(o: &mut Vec<Tok>, k: i64) {
    o.push(Tok::Kw(k));
}
fn st(o: &mut Vec<Tok>, s: &str) {
    o.push(Tok::S(s.to_string()));
}
fn int(o: &mut Vec<Tok>, i: i64) {
    o.push(Tok::I(i));
}
pub fn enc_strs(o: &mut Vec<Tok>, xs: &[String]) {
    int(o, xs.len() as i64);
    for x in xs {
        st(o, x);
    }
}
fn enc_unit(o: &mut Vec<Tok>, u: &Unit) {
    match u {
        Unit::Money(c) => {
            kw(o, 300);
            st(o, c);
        }
        Unit::Count => kw(o, 301),
        Unit::Duration => kw(o, 302),
        Unit::Instant => kw(o, 303),
        Unit::Bytes => kw(o, 304),
        Unit::Ratio => kw(o, 305),
    }
}
fn enc_q(o: &mut Vec<Tok>, q: &Q) {
    enc_unit(o, &q.u);
    int(o, q.n);
}
fn enc_ty(o: &mut Vec<Tok>, t: &Ty) {
    match t {
        Ty::Q(u) => {
            kw(o, 310);
            enc_unit(o, u);
        }
        Ty::S => kw(o, 311),
    }
}
fn enc_atom(o: &mut Vec<Tok>, a: &Atom) {
    match a {
        Atom::Q(q) => {
            kw(o, 320);
            enc_q(o, q);
        }
        Atom::S(s) => {
            kw(o, 321);
            st(o, s);
        }
    }
}
fn enc_v(o: &mut Vec<Tok>, v: &V) {
    match v {
        V::Q(q) => {
            kw(o, 330);
            enc_q(o, q);
        }
        V::S(s) => {
            kw(o, 331);
            st(o, s);
        }
        V::Set(items) => {
            kw(o, 332);
            int(o, items.len() as i64);
            for a in items {
                enc_atom(o, a);
            }
        }
    }
}
fn enc_term(o: &mut Vec<Tok>, t: &Term) {
    match t {
        Term::Param(p, ty) => {
            kw(o, 340);
            st(o, p);
            enc_ty(o, ty);
        }
        Term::Lit(v) => {
            kw(o, 341);
            enc_v(o, v);
        }
        Term::HistAgg(b, u) => {
            kw(o, 342);
            st(o, b);
            enc_unit(o, u);
        }
    }
}
fn op_idx(op: Op) -> i64 {
    match op {
        Op::Eq => 0,
        Op::Ne => 1,
        Op::Lt => 2,
        Op::Lte => 3,
        Op::Gt => 4,
        Op::Gte => 5,
        Op::In => 6,
        Op::Nin => 7,
    }
}
fn enc_op(o: &mut Vec<Tok>, op: Op) {
    kw(o, 350 + op_idx(op));
}
fn enc_cond(o: &mut Vec<Tok>, c: &Cond) {
    match c {
        Cond::True => kw(o, 360),
        Cond::Cmp(op, l, r) => {
            kw(o, 361);
            enc_op(o, *op);
            enc_term(o, l);
            enc_term(o, r);
        }
        Cond::And(x, y) => {
            kw(o, 362);
            enc_cond(o, x);
            enc_cond(o, y);
        }
        Cond::Or(x, y) => {
            kw(o, 363);
            enc_cond(o, x);
            enc_cond(o, y);
        }
        Cond::Not(x) => {
            kw(o, 364);
            enc_cond(o, x);
        }
    }
}
fn enc_part(o: &mut Vec<Tok>, p: &ResPart) {
    match p {
        ResPart::Exact(id) => {
            kw(o, 375);
            st(o, id);
        }
        ResPart::OneOf(ids) => {
            kw(o, 376);
            enc_strs(o, ids);
        }
        ResPart::Related(rel, anchor) => {
            kw(o, 377);
            st(o, rel);
            st(o, anchor);
        }
    }
}
fn enc_res_sel(o: &mut Vec<Tok>, s: &ResSel) {
    match s {
        ResSel::Exact(id) => {
            kw(o, 370);
            st(o, id);
        }
        ResSel::OneOf(ids) => {
            kw(o, 371);
            enc_strs(o, ids);
        }
        ResSel::Related(rel, anchor) => {
            kw(o, 372);
            st(o, rel);
            st(o, anchor);
        }
        ResSel::AnyRes(r) => {
            kw(o, 373);
            st(o, r);
        }
        ResSel::AllOf(ps) => {
            kw(o, 374);
            int(o, ps.len() as i64);
            for p in ps {
                enc_part(o, p);
            }
        }
    }
}
fn enc_agg(o: &mut Vec<Tok>, a: Agg) {
    kw(
        o,
        match a {
            Agg::Count => 400,
            Agg::Sum => 401,
            Agg::Max => 402,
            Agg::Distinct => 403,
        },
    );
}
fn enc_sel(o: &mut Vec<Tok>, s: &Sel) {
    match s {
        Sel::Gids(g) => {
            kw(o, 410);
            enc_strs(o, g);
        }
        Sel::Effect(c) => {
            kw(o, 411);
            st(o, c);
        }
    }
}
fn enc_window(o: &mut Vec<Tok>, w: &Window) {
    match w {
        Window::Task => kw(o, 420),
        Window::Sliding(ms) => {
            kw(o, 421);
            int(o, *ms);
        }
        Window::Period(ms, t0) => {
            kw(o, 422);
            int(o, *ms);
            int(o, *t0);
        }
        Window::Lifetime => kw(o, 423),
    }
}
fn enc_scope(o: &mut Vec<Tok>, s: &Scope) {
    match s {
        Scope::Session => kw(o, 430),
        Scope::Principal => kw(o, 431),
        Scope::Org => kw(o, 432),
        Scope::Fleet(a) => {
            kw(o, 433);
            enc_strs(o, a);
        }
    }
}
fn enc_on_exceed(o: &mut Vec<Tok>, e: OnExceed) {
    kw(o, if e == OnExceed::Deny { 440 } else { 441 });
}
fn enc_bcore(o: &mut Vec<Tok>, b: &BCore) {
    kw(o, 450);
    enc_agg(o, b.agg);
    enc_term(o, &b.value);
    st(o, &b.key);
    enc_window(o, &b.window);
    enc_scope(o, &b.scope);
    enc_q(o, &b.cap);
    enc_on_exceed(o, b.on_exceed);
}
fn enc_validity(o: &mut Vec<Tok>, v: &Validity) {
    kw(o, 460);
    int(o, v.not_before);
    int(o, v.not_after);
    int(o, v.max_idle);
}
fn enc_deleg(o: &mut Vec<Tok>, d: &Delegation) {
    kw(o, 461);
    int(o, d.max_depth);
    int(o, d.narrow_only as i64);
    enc_strs(o, &d.may_touch);
}
fn enc_grant(o: &mut Vec<Tok>, g: &Grant) {
    kw(o, 380);
    st(o, &g.gid);
    st(o, &g.verb);
    enc_res_sel(o, &g.res);
    enc_cond(o, &g.cond);
}
fn enc_prohibit(o: &mut Vec<Tok>, p: &Prohibit) {
    kw(o, 392);
    st(o, &p.pid);
    match &p.target {
        ProhTarget::Verb(v) => {
            kw(o, 390);
            st(o, v);
        }
        ProhTarget::Effect(c) => {
            kw(o, 391);
            st(o, c);
        }
    }
    enc_res_sel(o, &p.res);
    enc_cond(o, &p.cond);
}
fn enc_bound(o: &mut Vec<Tok>, b: &Bound) {
    kw(o, 451);
    st(o, &b.bid);
    enc_sel(o, &b.sel);
    enc_bcore(o, &b.core);
}
fn enc_hole(o: &mut Vec<Tok>, h: &Hole) {
    kw(o, 470);
    st(o, &h.hid);
    st(o, &h.q);
    enc_strs(o, &h.domain);
    enc_strs(o, &h.affects);
    int(o, h.global as i64);
}
/// `Render(g)`: the card as a token tape.
pub fn enc_goal(g: &Goal) -> Vec<Tok> {
    let mut o = vec![Tok::Kw(480), Tok::I(g.v), Tok::S(g.principal.clone()), Tok::S(g.ont_digest.clone()), Tok::S(g.nl_digest.clone())];
    enc_strs(&mut o, &g.sources);
    int(&mut o, g.grants.len() as i64);
    g.grants.iter().for_each(|x| enc_grant(&mut o, x));
    int(&mut o, g.prohibits.len() as i64);
    g.prohibits.iter().for_each(|x| enc_prohibit(&mut o, x));
    int(&mut o, g.bounds.len() as i64);
    g.bounds.iter().for_each(|x| enc_bound(&mut o, x));
    enc_validity(&mut o, &g.validity);
    enc_deleg(&mut o, &g.deleg);
    int(&mut o, g.escalate_on.len() as i64);
    g.escalate_on.iter().for_each(|x| enc_cond(&mut o, x));
    enc_strs(&mut o, &g.wildcard_ack);
    int(&mut o, g.holes.len() as i64);
    g.holes.iter().for_each(|x| enc_hole(&mut o, x));
    o
}

// ---- the compiled policy
fn enc_res_pat(o: &mut Vec<Tok>, p: &ResPat) {
    match p {
        ResPat::Star => kw(o, 630),
        ResPat::Set(ids) => {
            kw(o, 631);
            enc_strs(o, ids);
        }
    }
}
fn enc_nc(o: &mut Vec<Tok>, c: &NC) {
    match c {
        NC::True => kw(o, 600),
        NC::False => kw(o, 601),
        NC::Atom(op, l, r) => {
            kw(o, 602);
            enc_op(o, *op);
            enc_term(o, l);
            enc_term(o, r);
        }
        NC::And(x, y) => {
            kw(o, 603);
            enc_nc(o, x);
            enc_nc(o, y);
        }
        NC::Or(x, y) => {
            kw(o, 604);
            enc_nc(o, x);
            enc_nc(o, y);
        }
    }
}
pub fn enc_pol(p: &Pol) -> Vec<Tok> {
    let mut o = vec![Tok::Kw(650)];
    int(&mut o, p.preds.len() as i64);
    for x in &p.preds {
        kw(&mut o, 620);
        st(&mut o, &x.gid);
        st(&mut o, &x.verb);
        enc_res_pat(&mut o, &x.res);
        enc_nc(&mut o, &x.cond);
    }
    int(&mut o, p.prohs.len() as i64);
    for x in &p.prohs {
        kw(&mut o, 640);
        st(&mut o, &x.pid);
        enc_strs(&mut o, &x.verbs);
        enc_res_pat(&mut o, &x.res);
        enc_nc(&mut o, &x.cond);
    }
    int(&mut o, p.ceils.len() as i64);
    for x in &p.ceils {
        kw(&mut o, 610);
        st(&mut o, &x.bid);
        enc_strs(&mut o, &x.sel.gids);
        enc_strs(&mut o, &x.sel.verbs);
        enc_bcore(&mut o, &x.core);
    }
    int(&mut o, p.escs.len() as i64);
    for x in &p.escs {
        enc_nc(&mut o, x);
    }
    enc_validity(&mut o, &p.validity);
    enc_deleg(&mut o, &p.deleg);
    o
}

// ---- decoding (a cursor; every failure aborts the whole parse, as `Fail` does)
pub struct Rd<'a> {
    ts: &'a [Tok],
    i: usize,
}
type R<T> = Option<T>;
impl<'a> Rd<'a> {
    pub fn new(ts: &'a [Tok]) -> Self {
        Rd { ts, i: 0 }
    }
    pub fn done(&self) -> bool {
        self.i >= self.ts.len()
    }
    fn next(&mut self) -> R<&'a Tok> {
        let t = self.ts.get(self.i)?;
        self.i += 1;
        Some(t)
    }
    fn kw(&mut self) -> R<i64> {
        match self.next()? {
            Tok::Kw(k) => Some(*k),
            _ => None,
        }
    }
    fn expect(&mut self, k: i64) -> R<()> {
        if self.kw()? == k {
            Some(())
        } else {
            None
        }
    }
    fn int(&mut self) -> R<i64> {
        match self.next()? {
            Tok::I(i) => Some(*i),
            _ => None,
        }
    }
    fn str(&mut self) -> R<String> {
        match self.next()? {
            Tok::S(s) => Some(s.clone()),
            _ => None,
        }
    }
    fn bool(&mut self) -> R<bool> {
        match self.int()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    fn list<T>(&mut self, mut f: impl FnMut(&mut Self) -> R<T>) -> R<Vec<T>> {
        let n = self.int()?;
        if n < 0 {
            return None;
        }
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(f(self)?);
        }
        Some(v)
    }
    fn strs(&mut self) -> R<Vec<String>> {
        self.list(|r| r.str())
    }
    fn unit(&mut self) -> R<Unit> {
        match self.kw()? {
            300 => Some(Unit::Money(self.str()?)),
            301 => Some(Unit::Count),
            302 => Some(Unit::Duration),
            303 => Some(Unit::Instant),
            304 => Some(Unit::Bytes),
            305 => Some(Unit::Ratio),
            _ => None,
        }
    }
    fn q(&mut self) -> R<Q> {
        let u = self.unit()?;
        Some(Q { u, n: self.int()? })
    }
    fn ty(&mut self) -> R<Ty> {
        match self.kw()? {
            310 => Some(Ty::Q(self.unit()?)),
            311 => Some(Ty::S),
            _ => None,
        }
    }
    fn atom(&mut self) -> R<Atom> {
        match self.kw()? {
            320 => Some(Atom::Q(self.q()?)),
            321 => Some(Atom::S(self.str()?)),
            _ => None,
        }
    }
    fn v(&mut self) -> R<V> {
        match self.kw()? {
            330 => Some(V::Q(self.q()?)),
            331 => Some(V::S(self.str()?)),
            332 => Some(V::Set(self.list(|r| r.atom())?)),
            _ => None,
        }
    }
    fn term(&mut self) -> R<Term> {
        match self.kw()? {
            340 => {
                let p = self.str()?;
                Some(Term::Param(p, self.ty()?))
            }
            341 => Some(Term::Lit(self.v()?)),
            342 => {
                let b = self.str()?;
                Some(Term::HistAgg(b, self.unit()?))
            }
            _ => None,
        }
    }
    fn op(&mut self) -> R<Op> {
        match self.kw()? {
            350 => Some(Op::Eq),
            351 => Some(Op::Ne),
            352 => Some(Op::Lt),
            353 => Some(Op::Lte),
            354 => Some(Op::Gt),
            355 => Some(Op::Gte),
            356 => Some(Op::In),
            357 => Some(Op::Nin),
            _ => None,
        }
    }
    /// `fuel` is the remaining token count at the top: every node consumes a token, so it never limits a real condition.
    fn cond(&mut self, fuel: usize) -> R<Cond> {
        if fuel == 0 {
            return None;
        }
        match self.kw()? {
            360 => Some(Cond::True),
            361 => {
                let op = self.op()?;
                let l = self.term()?;
                Some(Cond::Cmp(op, l, self.term()?))
            }
            362 => {
                let x = self.cond(fuel - 1)?;
                Some(Cond::And(Box::new(x), Box::new(self.cond(fuel - 1)?)))
            }
            363 => {
                let x = self.cond(fuel - 1)?;
                Some(Cond::Or(Box::new(x), Box::new(self.cond(fuel - 1)?)))
            }
            364 => Some(Cond::Not(Box::new(self.cond(fuel - 1)?))),
            _ => None,
        }
    }
    fn cond_top(&mut self) -> R<Cond> {
        let fuel = self.ts.len() - self.i;
        self.cond(fuel)
    }
    fn part(&mut self) -> R<ResPart> {
        match self.kw()? {
            375 => Some(ResPart::Exact(self.str()?)),
            376 => Some(ResPart::OneOf(self.strs()?)),
            377 => {
                let rel = self.str()?;
                Some(ResPart::Related(rel, self.str()?))
            }
            _ => None,
        }
    }
    fn res_sel(&mut self) -> R<ResSel> {
        match self.kw()? {
            370 => Some(ResSel::Exact(self.str()?)),
            371 => Some(ResSel::OneOf(self.strs()?)),
            372 => {
                let rel = self.str()?;
                Some(ResSel::Related(rel, self.str()?))
            }
            373 => Some(ResSel::AnyRes(self.str()?)),
            374 => Some(ResSel::AllOf(self.list(|r| r.part())?)),
            _ => None,
        }
    }
    fn grant(&mut self) -> R<Grant> {
        self.expect(380)?;
        let gid = self.str()?;
        let verb = self.str()?;
        let res = self.res_sel()?;
        Some(Grant { gid, verb, res, cond: self.cond_top()? })
    }
    fn prohibit(&mut self) -> R<Prohibit> {
        self.expect(392)?;
        let pid = self.str()?;
        let target = match self.kw()? {
            390 => ProhTarget::Verb(self.str()?),
            391 => ProhTarget::Effect(self.str()?),
            _ => return None,
        };
        let res = self.res_sel()?;
        Some(Prohibit { pid, target, res, cond: self.cond_top()? })
    }
    fn agg(&mut self) -> R<Agg> {
        match self.kw()? {
            400 => Some(Agg::Count),
            401 => Some(Agg::Sum),
            402 => Some(Agg::Max),
            403 => Some(Agg::Distinct),
            _ => None,
        }
    }
    fn sel(&mut self) -> R<Sel> {
        match self.kw()? {
            410 => Some(Sel::Gids(self.strs()?)),
            411 => Some(Sel::Effect(self.str()?)),
            _ => None,
        }
    }
    fn window(&mut self) -> R<Window> {
        match self.kw()? {
            420 => Some(Window::Task),
            421 => Some(Window::Sliding(self.int()?)),
            422 => {
                let ms = self.int()?;
                Some(Window::Period(ms, self.int()?))
            }
            423 => Some(Window::Lifetime),
            _ => None,
        }
    }
    fn scope(&mut self) -> R<Scope> {
        match self.kw()? {
            430 => Some(Scope::Session),
            431 => Some(Scope::Principal),
            432 => Some(Scope::Org),
            433 => Some(Scope::Fleet(self.strs()?)),
            _ => None,
        }
    }
    fn on_exceed(&mut self) -> R<OnExceed> {
        match self.kw()? {
            440 => Some(OnExceed::Deny),
            441 => Some(OnExceed::Escalate),
            _ => None,
        }
    }
    fn bcore(&mut self) -> R<BCore> {
        self.expect(450)?;
        let agg = self.agg()?;
        let value = self.term()?;
        let key = self.str()?;
        let window = self.window()?;
        let scope = self.scope()?;
        let cap = self.q()?;
        Some(BCore { agg, value, key, window, scope, cap, on_exceed: self.on_exceed()? })
    }
    fn bound(&mut self) -> R<Bound> {
        self.expect(451)?;
        let bid = self.str()?;
        let sel = self.sel()?;
        Some(Bound { bid, sel, core: self.bcore()? })
    }
    fn validity(&mut self) -> R<Validity> {
        self.expect(460)?;
        let not_before = self.int()?;
        let not_after = self.int()?;
        Some(Validity { not_before, not_after, max_idle: self.int()? })
    }
    fn deleg(&mut self) -> R<Delegation> {
        self.expect(461)?;
        let max_depth = self.int()?;
        let narrow_only = self.bool()?;
        Some(Delegation { max_depth, narrow_only, may_touch: self.strs()? })
    }
    fn hole(&mut self) -> R<Hole> {
        self.expect(470)?;
        let hid = self.str()?;
        let q = self.str()?;
        let domain = self.strs()?;
        let affects = self.strs()?;
        Some(Hole { hid, q, domain, affects, global: self.bool()? })
    }
    fn goal(&mut self) -> R<Goal> {
        self.expect(480)?;
        let v = self.int()?;
        let principal = self.str()?;
        let ont_digest = self.str()?;
        let nl_digest = self.str()?;
        let sources = self.strs()?;
        let grants = self.list(|r| r.grant())?;
        let prohibits = self.list(|r| r.prohibit())?;
        let bounds = self.list(|r| r.bound())?;
        let validity = self.validity()?;
        let deleg = self.deleg()?;
        let escalate_on = self.list(|r| r.cond_top())?;
        let wildcard_ack = self.strs()?;
        let holes = self.list(|r| r.hole())?;
        Some(Goal { v, principal, ont_digest, nl_digest, sources, grants, prohibits, bounds, validity, deleg, escalate_on, wildcard_ack, holes })
    }
    // ---- ontology, action, history (Goal.dfy)
    fn param_decl(&mut self) -> R<ParamDecl> {
        self.expect(500)?;
        let path = self.str()?;
        Some(ParamDecl { path, ty: self.ty()? })
    }
    fn verb_decl(&mut self) -> R<VerbDecl> {
        self.expect(501)?;
        let verb = self.str()?;
        let cls = self.str()?;
        Some(VerbDecl { verb, cls, params: self.list(|r| r.param_decl())? })
    }
    fn rel_decl(&mut self) -> R<RelDecl> {
        self.expect(502)?;
        let rel = self.str()?;
        let anchor = self.str()?;
        Some(RelDecl { rel, anchor, members: self.strs()? })
    }
    fn ontology(&mut self) -> R<Ontology> {
        self.expect(510)?;
        let verbs = self.list(|r| r.verb_decl())?;
        Some(Ontology { verbs, rels: self.list(|r| r.rel_decl())? })
    }
    fn act(&mut self) -> R<Act> {
        self.expect(530)?;
        let verb = self.str()?;
        let res = self.str()?;
        // a later entry for the same key replaces an earlier one
        let entries = self.list(|r| {
            r.expect(520)?;
            let k = r.str()?;
            Some((k, r.v()?))
        })?;
        let params: HashMap<String, V> = entries.into_iter().collect();
        let t = self.int()?;
        let sess = self.str()?;
        let prin = self.str()?;
        let org = self.str()?;
        let agent = self.str()?;
        Some(Act { verb, res, params, t, sess, prin, org, agent, depth: self.int()? })
    }
    fn adm(&mut self) -> R<Adm> {
        self.expect(531)?;
        let gid = self.str()?;
        Some(Adm { gid, act: self.act()? })
    }
    fn hist(&mut self) -> R<Hist> {
        self.expect(541)?;
        let adms = self.list(|r| r.adm())?;
        let last = self.int()?;
        let entries = self.list(|r| {
            r.expect(540)?;
            let k = r.str()?;
            Some((k, r.q()?))
        })?;
        Some(Hist { adms, last, aggs: entries.into_iter().collect() })
    }
}

/// `Parse`: a whole-tape goal (nothing left over).
pub fn parse_goal(ts: &[Tok]) -> Option<Goal> {
    let mut r = Rd::new(ts);
    let g = r.goal()?;
    r.done().then_some(g)
}
pub fn parse_ontology(ts: &[Tok]) -> Option<Ontology> {
    let mut r = Rd::new(ts);
    let g = r.ontology()?;
    r.done().then_some(g)
}
pub fn parse_act(ts: &[Tok]) -> Option<Act> {
    let mut r = Rd::new(ts);
    let g = r.act()?;
    r.done().then_some(g)
}
pub fn parse_hist(ts: &[Tok]) -> Option<Hist> {
    let mut r = Rd::new(ts);
    let g = r.hist()?;
    r.done().then_some(g)
}
