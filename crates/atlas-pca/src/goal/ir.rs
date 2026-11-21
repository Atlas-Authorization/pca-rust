//! The Goal IR of goal-to-decision: datatypes, reference semantics `D_G` and the typing judgement, a hand port of the proved
//! Dafny model `formal/dafny/GoalIr.dfy`. Numbers are exact integers (arithmetic that can leave `i64` runs in `i128`), strings
//! are Unicode scalar sequences (the tape syntax carries code points), Dafny sequences are `Vec`s.
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// A decision: 0 deny, 1 escalate, 2 allow (meet is `min`, join is `max`).
pub type Dec = u8;
pub const DENY: Dec = 0;
pub const ESCALATE: Dec = 1;
pub const ALLOW: Dec = 2;
/// Kleene truth: 0 false, 1 unknown, 2 true.
pub type Tri = u8;
pub const KF: Tri = 0;
pub const KU: Tri = 1;
pub const KT: Tri = 2;

pub fn meet_d(a: Dec, b: Dec) -> Dec {
    a.min(b)
}
pub fn join_d(a: Dec, b: Dec) -> Dec {
    a.max(b)
}
pub fn and_k(a: Tri, b: Tri) -> Tri {
    a.min(b)
}
pub fn or_k(a: Tri, b: Tri) -> Tri {
    a.max(b)
}
pub fn not_k(a: Tri) -> Tri {
    2 - a
}
pub fn b2t(b: bool) -> Tri {
    if b {
        KT
    } else {
        KF
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    Money(String),
    Count,
    Duration,
    Instant,
    Bytes,
    Ratio,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Q {
    pub u: Unit,
    pub n: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Atom {
    Q(Q),
    S(String),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum V {
    Q(Q),
    S(String),
    Set(Vec<Atom>),
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Ty {
    Q(Unit),
    S,
}
pub fn atom_v(a: &Atom) -> V {
    match a {
        Atom::Q(q) => V::Q(q.clone()),
        Atom::S(s) => V::S(s.clone()),
    }
}
pub fn type_of_v(v: &V) -> Option<Ty> {
    match v {
        V::Q(q) => Some(Ty::Q(q.u.clone())),
        V::S(_) => Some(Ty::S),
        V::Set(_) => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    Param(String, Ty),
    Lit(V),
    HistAgg(String, Unit),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    Nin,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cond {
    True,
    Cmp(Op, Term, Term),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResPart {
    Exact(String),
    OneOf(Vec<String>),
    Related(String, String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResSel {
    Exact(String),
    OneOf(Vec<String>),
    Related(String, String),
    AnyRes(String),
    AllOf(Vec<ResPart>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub gid: String,
    pub verb: String,
    pub res: ResSel,
    pub cond: Cond,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProhTarget {
    Verb(String),
    Effect(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prohibit {
    pub pid: String,
    pub target: ProhTarget,
    pub res: ResSel,
    pub cond: Cond,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agg {
    Count,
    Sum,
    Max,
    Distinct,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sel {
    Gids(Vec<String>),
    Effect(String),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Window {
    Task,
    Sliding(i64),
    Period(i64, i64),
    Lifetime,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Session,
    Principal,
    Org,
    Fleet(Vec<String>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnExceed {
    Deny,
    Escalate,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BCore {
    pub agg: Agg,
    pub value: Term,
    pub key: String,
    pub window: Window,
    pub scope: Scope,
    pub cap: Q,
    pub on_exceed: OnExceed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    pub bid: String,
    pub sel: Sel,
    pub core: BCore,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
    pub max_idle: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delegation {
    pub max_depth: i64,
    pub narrow_only: bool,
    pub may_touch: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hole {
    pub hid: String,
    pub q: String,
    pub domain: Vec<String>,
    pub affects: Vec<String>,
    pub global: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Goal {
    pub v: i64,
    pub principal: String,
    pub ont_digest: String,
    pub nl_digest: String,
    pub sources: Vec<String>,
    pub grants: Vec<Grant>,
    pub prohibits: Vec<Prohibit>,
    pub bounds: Vec<Bound>,
    pub validity: Validity,
    pub deleg: Delegation,
    pub escalate_on: Vec<Cond>,
    pub wildcard_ack: Vec<String>,
    pub holes: Vec<Hole>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamDecl {
    pub path: String,
    pub ty: Ty,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerbDecl {
    pub verb: String,
    pub cls: String,
    pub params: Vec<ParamDecl>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelDecl {
    pub rel: String,
    pub anchor: String,
    pub members: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ontology {
    pub verbs: Vec<VerbDecl>,
    pub rels: Vec<RelDecl>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Act {
    pub verb: String,
    pub res: String,
    pub params: HashMap<String, V>,
    pub t: i64,
    pub sess: String,
    pub prin: String,
    pub org: String,
    pub agent: String,
    pub depth: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adm {
    pub gid: String,
    pub act: Act,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hist {
    pub adms: Vec<Adm>,
    pub last: i64,
    pub aggs: HashMap<String, Q>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResPat {
    Star,
    Set(Vec<String>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LSel {
    pub gids: Vec<String>,
    pub verbs: Vec<String>,
}

pub fn res_ok(p: &ResPat, r: &str) -> bool {
    match p {
        ResPat::Star => true,
        ResPat::Set(ids) => ids.iter().any(|i| i == r),
    }
}
pub fn rel_members(rels: &[RelDecl], rel: &str, anchor: &str) -> Vec<String> {
    rels.iter().find(|r| r.rel == rel && r.anchor == anchor).map(|r| r.members.clone()).unwrap_or_default()
}
fn inter_pat(x: ResPat, y: ResPat) -> ResPat {
    match (x, y) {
        (ResPat::Star, y) => y,
        (x, ResPat::Star) => x,
        (ResPat::Set(a), ResPat::Set(b)) => ResPat::Set(a.into_iter().filter(|s| b.contains(s)).collect()),
    }
}
pub fn resolve_part(ont: &Ontology, p: &ResPart) -> ResPat {
    match p {
        ResPart::Exact(id) => ResPat::Set(vec![id.clone()]),
        ResPart::OneOf(ids) => ResPat::Set(ids.clone()),
        ResPart::Related(rel, anchor) => ResPat::Set(rel_members(&ont.rels, rel, anchor)),
    }
}
/// Right fold, exactly `ResolveParts`: the first part is filtered by the intersection of the rest.
pub fn resolve_parts(ont: &Ontology, ps: &[ResPart]) -> ResPat {
    match ps.split_first() {
        None => ResPat::Star,
        Some((p0, rest)) => inter_pat(resolve_part(ont, p0), resolve_parts(ont, rest)),
    }
}
pub fn resolve_sel(ont: &Ontology, s: &ResSel) -> ResPat {
    match s {
        ResSel::Exact(id) => ResPat::Set(vec![id.clone()]),
        ResSel::OneOf(ids) => ResPat::Set(ids.clone()),
        ResSel::Related(rel, anchor) => ResPat::Set(rel_members(&ont.rels, rel, anchor)),
        ResSel::AnyRes(_) => ResPat::Star,
        ResSel::AllOf(ps) => resolve_parts(ont, ps),
    }
}
pub fn verbs_of_class(vs: &[VerbDecl], cls: &str) -> Vec<String> {
    vs.iter().filter(|v| v.cls == cls).map(|v| v.verb.clone()).collect()
}
pub fn resolve_bsel(ont: &Ontology, s: &Sel) -> LSel {
    match s {
        Sel::Gids(g) => LSel { gids: g.clone(), verbs: vec![] },
        Sel::Effect(c) => LSel { gids: vec![], verbs: verbs_of_class(&ont.verbs, c) },
    }
}
pub fn proh_verbs(ont: &Ontology, t: &ProhTarget) -> Vec<String> {
    match t {
        ProhTarget::Verb(v) => vec![v.clone()],
        ProhTarget::Effect(c) => verbs_of_class(&ont.verbs, c),
    }
}

// ---- evaluation (Kleene, as PolicyVm Tri)
pub fn eq_t(x: &V, y: &V) -> Tri {
    match (x, y) {
        (V::Q(p), V::Q(q)) => {
            if p.u == q.u {
                b2t(p.n == q.n)
            } else {
                KU
            }
        }
        (V::S(s), V::S(t)) => b2t(s == t),
        _ => KU,
    }
}
pub fn lt_t(x: &V, y: &V) -> Tri {
    match (x, y) {
        (V::Q(p), V::Q(q)) => {
            if p.u == q.u {
                b2t(p.n < q.n)
            } else {
                KU
            }
        }
        _ => KU,
    }
}
pub fn in_t(x: &V, items: &[Atom]) -> Tri {
    let mut r = KF;
    for it in items {
        r = or_k(r, eq_t(x, &atom_v(it)));
    }
    r
}
pub fn cmp_t(op: Op, x: Option<&V>, y: Option<&V>) -> Tri {
    let (x, y) = match (x, y) {
        (Some(x), Some(y)) => (x, y),
        _ => return KU,
    };
    let set_in = |x: &V, y: &V| match y {
        V::Set(items) => in_t(x, items),
        _ => KU,
    };
    match op {
        Op::Eq => eq_t(x, y),
        Op::Ne => not_k(eq_t(x, y)),
        Op::Lt => lt_t(x, y),
        Op::Gte => not_k(lt_t(x, y)),
        Op::Gt => lt_t(y, x),
        Op::Lte => not_k(lt_t(y, x)),
        Op::In => set_in(x, y),
        Op::Nin => not_k(set_in(x, y)),
    }
}
pub fn neg_op(op: Op) -> Op {
    match op {
        Op::Eq => Op::Ne,
        Op::Ne => Op::Eq,
        Op::Lt => Op::Gte,
        Op::Gte => Op::Lt,
        Op::Gt => Op::Lte,
        Op::Lte => Op::Gt,
        Op::In => Op::Nin,
        Op::Nin => Op::In,
    }
}
pub fn eval_t<'a>(t: &'a Term, a: &'a Act, h: &'a Hist) -> Option<Cow<'a, V>> {
    match t {
        Term::Param(p, _) => a.params.get(p).map(Cow::Borrowed),
        Term::Lit(v) => Some(Cow::Borrowed(v)),
        Term::HistAgg(b, _) => h.aggs.get(b).map(|q| Cow::Owned(V::Q(q.clone()))),
    }
}
pub fn eval_c(c: &Cond, a: &Act, h: &Hist) -> Tri {
    match c {
        Cond::True => KT,
        Cond::Cmp(op, l, r) => {
            let x = eval_t(l, a, h);
            let y = eval_t(r, a, h);
            cmp_t(*op, x.as_deref(), y.as_deref())
        }
        Cond::And(x, y) => and_k(eval_c(x, a, h), eval_c(y, a, h)),
        Cond::Or(x, y) => or_k(eval_c(x, a, h), eval_c(y, a, h)),
        Cond::Not(x) => not_k(eval_c(x, a, h)),
    }
}

// ---- bounds
pub fn applies_l(s: &LSel, gid: &str, verb: &str) -> bool {
    s.gids.iter().any(|g| g == gid) || s.verbs.iter().any(|v| v == verb)
}
pub fn in_scope(sc: &Scope, a: &Act, x: &Act) -> bool {
    match sc {
        Scope::Session => a.sess == x.sess,
        Scope::Principal => a.prin == x.prin,
        Scope::Org => a.org == x.org,
        Scope::Fleet(ag) => ag.contains(&a.agent) && ag.contains(&x.agent),
    }
}
pub fn in_window(w: &Window, a: &Act, x: &Act) -> bool {
    let (at, xt) = (a.t as i128, x.t as i128);
    match w {
        Window::Task | Window::Lifetime => true,
        Window::Sliding(ms) => xt > at - (*ms as i128) && xt <= at,
        Window::Period(ms, t0) => {
            let (ms, t0) = (*ms as i128, *t0 as i128);
            // Dafny integer division is Euclidean; ms > 0 here, so it is floor division
            ms > 0 && (at - t0).div_euclid(ms) == (xt - t0).div_euclid(ms)
        }
    }
}
/// The admitted actions this bound counts, followed by the candidate itself.
pub fn sel_items<'a>(core: &BCore, s: &LSel, adms: &'a [Adm], a: &'a Act) -> Vec<&'a Act> {
    let mut v: Vec<&'a Act> = Vec::new();
    for m in adms {
        if applies_l(s, &m.gid, &m.act.verb) && in_scope(&core.scope, a, &m.act) && in_window(&core.window, a, &m.act) {
            v.push(&m.act);
        }
    }
    v.push(a);
    v
}
fn item_vals(core: &BCore, items: &[&Act], h: &Hist) -> Option<Vec<i128>> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match eval_t(&core.value, it, h).as_deref() {
            Some(V::Q(q)) if q.u == core.cap.u => out.push(q.n as i128),
            _ => return None,
        }
    }
    Some(out)
}
fn key_vals<'a>(core: &BCore, items: &[&'a Act]) -> Option<Vec<&'a V>> {
    let mut out = Vec::with_capacity(items.len());
    for it in items.iter().copied() {
        out.push(it.params.get(&core.key)?);
    }
    Some(out)
}
/// The aggregate of the selected items, compared with the cap: true / unknown / false = exceeded / unreadable / within.
pub fn exceeded(core: &BCore, items: &[&Act], h: &Hist) -> Tri {
    let cap = core.cap.n as i128;
    match core.agg {
        Agg::Count => b2t((items.len() as i128) > cap),
        Agg::Sum => match item_vals(core, items, h) {
            Some(xs) => b2t(xs.iter().sum::<i128>() > cap),
            None => KU,
        },
        Agg::Max => match item_vals(core, items, h) {
            Some(xs) => match xs.iter().max() {
                Some(m) => b2t(*m > cap),
                None => KU,
            },
            None => KU,
        },
        Agg::Distinct => match key_vals(core, items) {
            Some(vs) => {
                let set: HashSet<&V> = vs.into_iter().collect();
                b2t((set.len() as i128) > cap)
            }
            None => KU,
        },
    }
}
pub fn bound_stat(core: &BCore, s: &LSel, a: &Act, h: &Hist) -> Dec {
    let e = exceeded(core, &sel_items(core, s, &h.adms, a), h);
    if e == KT {
        match core.on_exceed {
            OnExceed::Deny => DENY,
            OnExceed::Escalate => ESCALATE,
        }
    } else if e == KU {
        ESCALATE
    } else {
        ALLOW
    }
}

// ---- the decision D_G
pub fn validity_dec(v: &Validity, dg: &Delegation, a: &Act, h: &Hist) -> Dec {
    if a.t < v.not_before || a.t > v.not_after {
        DENY
    } else if v.max_idle > 0 && h.last >= 0 && (a.t as i128 - h.last as i128) > v.max_idle as i128 {
        DENY
    } else if a.depth < 0 || a.depth > dg.max_depth {
        DENY
    } else {
        ALLOW
    }
}
pub fn deleg_ok(dg: &Delegation, gid: &str, a: &Act) -> bool {
    a.depth == 0 || dg.may_touch.iter().any(|g| g == gid)
}
pub fn tri_dec(m: Tri) -> Dec {
    m
}
fn proh_one(verbs: &[String], res: &ResPat, c: &Cond, a: &Act, h: &Hist) -> Dec {
    let m = and_k(b2t(verbs.iter().any(|v| *v == a.verb)), and_k(b2t(res_ok(res, &a.res)), eval_c(c, a, h)));
    if m == KT {
        DENY
    } else if m == KU {
        ESCALATE
    } else {
        ALLOW
    }
}
fn proh_dec_g(ont: &Ontology, ps: &[Prohibit], a: &Act, h: &Hist) -> Dec {
    let mut d = ALLOW;
    for p in ps {
        d = meet_d(d, proh_one(&proh_verbs(ont, &p.target), &resolve_sel(ont, &p.res), &p.cond, a, h));
    }
    d
}
pub fn esc_one(m: Tri) -> Dec {
    if m == KF {
        ALLOW
    } else {
        ESCALATE
    }
}
fn esc_dec_g(cs: &[Cond], a: &Act, h: &Hist) -> Dec {
    let mut d = ALLOW;
    for c in cs {
        d = meet_d(d, esc_one(eval_c(c, a, h)));
    }
    d
}
fn bounds_dec_g(ont: &Ontology, bs: &[Bound], gid: &str, a: &Act, h: &Hist) -> Dec {
    let mut d = ALLOW;
    for b in bs {
        let s = resolve_bsel(ont, &b.sel);
        let x = if applies_l(&s, gid, &a.verb) { bound_stat(&b.core, &s, a, h) } else { ALLOW };
        d = meet_d(d, x);
    }
    d
}
fn grant_match(ont: &Ontology, g: &Grant, dg: &Delegation, a: &Act, h: &Hist) -> Tri {
    and_k(b2t(a.verb == g.verb && deleg_ok(dg, &g.gid, a)), and_k(b2t(res_ok(&resolve_sel(ont, &g.res), &a.res)), eval_c(&g.cond, a, h)))
}
fn grants_dec_g(ont: &Ontology, g: &Goal, a: &Act, h: &Hist) -> Dec {
    let mut d = DENY;
    for gr in &g.grants {
        d = join_d(d, meet_d(tri_dec(grant_match(ont, gr, &g.deleg, a, h)), bounds_dec_g(ont, &g.bounds, &gr.gid, a, h)));
    }
    d
}
/// Allow_G / Escalate_G / Deny_G as one total function. Closed world: a verb no grant names is Deny.
pub fn dg(ont: &Ontology, g: &Goal, a: &Act, h: &Hist) -> Dec {
    meet_d(
        validity_dec(&g.validity, &g.deleg, a, h),
        meet_d(proh_dec_g(ont, &g.prohibits, a, h), meet_d(esc_dec_g(&g.escalate_on, a, h), grants_dec_g(ont, g, a, h))),
    )
}

// ---- typing
pub fn strictly_sorted(xs: &[&str]) -> bool {
    xs.windows(2).all(|w| w[0] < w[1])
}
fn unit_ok(u: &Unit) -> bool {
    match u {
        Unit::Money(c) => !c.is_empty(),
        _ => true,
    }
}
fn ty_ok(t: &Ty) -> bool {
    match t {
        Ty::Q(u) => unit_ok(u),
        Ty::S => true,
    }
}
fn v_ok(v: &V) -> bool {
    match v {
        V::Q(q) => unit_ok(&q.u),
        V::S(_) => true,
        V::Set(items) => items.iter().all(|a| match a {
            Atom::Q(q) => unit_ok(&q.u),
            Atom::S(_) => true,
        }),
    }
}
pub fn type_of_term(t: &Term) -> Option<Ty> {
    match t {
        Term::Param(_, ty) => Some(ty.clone()),
        Term::Lit(v) => type_of_v(v),
        Term::HistAgg(_, u) => Some(Ty::Q(u.clone())),
    }
}
fn term_ok(t: &Term) -> bool {
    match t {
        Term::Param(p, ty) => !p.is_empty() && ty_ok(ty),
        Term::Lit(v) => v_ok(v),
        Term::HistAgg(b, u) => !b.is_empty() && unit_ok(u),
    }
}
fn cmp_typed(op: Op, l: &Term, r: &Term) -> bool {
    if !(term_ok(l) && term_ok(r)) {
        return false;
    }
    let tl = match type_of_term(l) {
        Some(t) => t,
        None => return false,
    };
    let same = type_of_term(r).as_ref() == Some(&tl);
    match op {
        Op::Eq | Op::Ne => same,
        Op::Lt | Op::Lte | Op::Gt | Op::Gte => same && matches!(tl, Ty::Q(_)),
        Op::In | Op::Nin => match r {
            Term::Lit(V::Set(items)) => items.iter().all(|a| type_of_v(&atom_v(a)).as_ref() == Some(&tl)),
            _ => false,
        },
    }
}
fn params_ok(t: &Term, ok: &dyn Fn(&str, &Ty) -> bool) -> bool {
    match t {
        Term::Param(p, ty) => ok(p, ty),
        _ => true,
    }
}
pub fn cond_typed(c: &Cond, ok: &dyn Fn(&str, &Ty) -> bool) -> bool {
    match c {
        Cond::True => true,
        Cond::Cmp(op, l, r) => cmp_typed(*op, l, r) && params_ok(l, ok) && params_ok(r, ok),
        Cond::And(x, y) | Cond::Or(x, y) => cond_typed(x, ok) && cond_typed(y, ok),
        Cond::Not(x) => cond_typed(x, ok),
    }
}
pub fn find_decl<'a>(vs: &'a [VerbDecl], verb: &str) -> Option<&'a VerbDecl> {
    vs.iter().find(|v| v.verb == verb)
}
fn declared_for(ont: &Ontology, verbs: &[String], p: &str, ty: &Ty) -> bool {
    verbs.iter().all(|v| find_decl(&ont.verbs, v).is_some_and(|d| d.params.iter().any(|pd| pd.path == p && pd.ty == *ty)))
}
fn no_conflict(vs: &[VerbDecl], p: &str, ty: &Ty) -> bool {
    vs.iter().all(|v| v.params.iter().all(|pd| pd.path != p || pd.ty == *ty))
}
fn rel_declared(ont: &Ontology, rel: &str, anchor: &str) -> bool {
    ont.rels.iter().any(|r| r.rel == rel && r.anchor == anchor)
}
fn part_ok(ont: &Ontology, p: &ResPart) -> bool {
    match p {
        ResPart::Exact(id) => !id.is_empty(),
        ResPart::OneOf(ids) => !ids.is_empty(),
        ResPart::Related(rel, anchor) => rel_declared(ont, rel, anchor),
    }
}
fn res_sel_ok(ont: &Ontology, s: &ResSel) -> bool {
    match s {
        ResSel::Exact(id) => !id.is_empty(),
        ResSel::OneOf(ids) => !ids.is_empty(),
        ResSel::Related(rel, anchor) => rel_declared(ont, rel, anchor),
        ResSel::AnyRes(_) => true,
        ResSel::AllOf(ps) => ps.len() >= 2 && ps.iter().all(|p| part_ok(ont, p)),
    }
}
pub fn grant_ok(ont: &Ontology, g: &Goal, gr: &Grant) -> bool {
    !gr.gid.is_empty()
        && find_decl(&ont.verbs, &gr.verb).is_some()
        && res_sel_ok(ont, &gr.res)
        && (!matches!(gr.res, ResSel::AnyRes(_)) || g.wildcard_ack.contains(&gr.gid))
        && cond_typed(&gr.cond, &|p: &str, ty: &Ty| declared_for(ont, std::slice::from_ref(&gr.verb), p, ty))
}
pub fn prohibit_ok(ont: &Ontology, p: &Prohibit) -> bool {
    let vs = proh_verbs(ont, &p.target);
    !p.pid.is_empty()
        && res_sel_ok(ont, &p.res)
        && (match &p.target {
            ProhTarget::Verb(v) => find_decl(&ont.verbs, v).is_some(),
            ProhTarget::Effect(c) => !c.is_empty() && !vs.is_empty(),
        })
        && cond_typed(&p.cond, &|q: &str, ty: &Ty| declared_for(ont, &vs, q, ty))
}
fn window_ok(w: &Window) -> bool {
    match w {
        Window::Sliding(ms) | Window::Period(ms, _) => *ms > 0,
        _ => true,
    }
}
fn scope_ok(s: &Scope) -> bool {
    match s {
        Scope::Fleet(ag) => !ag.is_empty(),
        _ => true,
    }
}
fn has_grant(g: &Goal, gid: &str) -> bool {
    g.grants.iter().any(|x| x.gid == gid)
}
pub fn bound_ok(_ont: &Ontology, g: &Goal, b: &Bound) -> bool {
    let c = &b.core;
    !b.bid.is_empty()
        && term_ok(&c.value)
        && unit_ok(&c.cap.u)
        && c.cap.n >= 0
        && window_ok(&c.window)
        && scope_ok(&c.scope)
        && (match &b.sel {
            Sel::Gids(gids) => !gids.is_empty() && gids.iter().all(|x| has_grant(g, x)),
            Sel::Effect(cl) => !cl.is_empty(),
        })
        && (match c.agg {
            Agg::Count => c.cap.u == Unit::Count,
            Agg::Sum | Agg::Max => type_of_term(&c.value) == Some(Ty::Q(c.cap.u.clone())),
            Agg::Distinct => c.cap.u == Unit::Count && !c.key.is_empty(),
        })
}
pub fn validity_ok(v: &Validity, dg: &Delegation, g: &Goal) -> bool {
    v.not_before <= v.not_after && v.max_idle >= 0 && (0..=16).contains(&dg.max_depth) && dg.narrow_only && dg.may_touch.iter().all(|x| has_grant(g, x))
}
pub fn hole_ok(g: &Goal, h: &Hole) -> bool {
    !h.hid.is_empty() && h.affects.iter().all(|x| has_grant(g, x))
}
pub fn escs_typed(ont: &Ontology, g: &Goal) -> bool {
    g.escalate_on.iter().all(|c| cond_typed(c, &|p: &str, ty: &Ty| no_conflict(&ont.verbs, p, ty)))
}
pub fn sorted4(g: &Goal) -> bool {
    let gids: Vec<&str> = g.grants.iter().map(|x| x.gid.as_str()).collect();
    let pids: Vec<&str> = g.prohibits.iter().map(|x| x.pid.as_str()).collect();
    let bids: Vec<&str> = g.bounds.iter().map(|x| x.bid.as_str()).collect();
    let hids: Vec<&str> = g.holes.iter().map(|x| x.hid.as_str()).collect();
    strictly_sorted(&gids) && strictly_sorted(&pids) && strictly_sorted(&bids) && strictly_sorted(&hids)
}
