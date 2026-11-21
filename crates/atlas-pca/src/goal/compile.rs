//! The deterministic compiler `C : Goal -> Policy | Escalate(reasons)`, its decision function `D_P`, and the witness-bearing
//! decision with its checker. Hand port of `formal/dafny/GoalCompile.dfy` and `GoalWitness.dfy`.
use super::ir::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NC {
    True,
    False,
    Atom(Op, Term, Term),
    And(Box<NC>, Box<NC>),
    Or(Box<NC>, Box<NC>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LPred {
    pub gid: String,
    pub verb: String,
    pub res: ResPat,
    pub cond: NC,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LProh {
    pub pid: String,
    pub verbs: Vec<String>,
    pub res: ResPat,
    pub cond: NC,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LCeil {
    pub bid: String,
    pub sel: LSel,
    pub core: BCore,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pol {
    pub preds: Vec<LPred>,
    pub prohs: Vec<LProh>,
    pub ceils: Vec<LCeil>,
    pub escs: Vec<NC>,
    pub validity: Validity,
    pub deleg: Delegation,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CResult {
    Compiled(Pol),
    Escalate(Vec<String>),
}

pub fn eval_n(c: &NC, a: &Act, h: &Hist) -> Tri {
    match c {
        NC::True => KT,
        NC::False => KF,
        NC::Atom(op, l, r) => {
            let x = eval_t(l, a, h);
            let y = eval_t(r, a, h);
            cmp_t(*op, x.as_deref(), y.as_deref())
        }
        NC::And(x, y) => and_k(eval_n(x, a, h), eval_n(y, a, h)),
        NC::Or(x, y) => or_k(eval_n(x, a, h), eval_n(y, a, h)),
    }
}
/// `pos` is the polarity: `nnf(c, false)` is the normal form of `not c`.
pub fn nnf(c: &Cond, pos: bool) -> NC {
    match c {
        Cond::True => {
            if pos {
                NC::True
            } else {
                NC::False
            }
        }
        Cond::Cmp(op, l, r) => NC::Atom(if pos { *op } else { neg_op(*op) }, l.clone(), r.clone()),
        Cond::And(x, y) => {
            let (a, b) = (Box::new(nnf(x, pos)), Box::new(nnf(y, pos)));
            if pos {
                NC::And(a, b)
            } else {
                NC::Or(a, b)
            }
        }
        Cond::Or(x, y) => {
            let (a, b) = (Box::new(nnf(x, pos)), Box::new(nnf(y, pos)));
            if pos {
                NC::Or(a, b)
            } else {
                NC::And(a, b)
            }
        }
        Cond::Not(x) => nnf(x, !pos),
    }
}

fn proh_dec_p(ps: &[LProh], a: &Act, h: &Hist) -> Dec {
    let mut d = ALLOW;
    for p in ps {
        let m = and_k(b2t(p.verbs.iter().any(|v| *v == a.verb)), and_k(b2t(res_ok(&p.res, &a.res)), eval_n(&p.cond, a, h)));
        let x = if m == KT {
            DENY
        } else if m == KU {
            ESCALATE
        } else {
            ALLOW
        };
        d = meet_d(d, x);
    }
    d
}
fn esc_dec_p(cs: &[NC], a: &Act, h: &Hist) -> Dec {
    let mut d = ALLOW;
    for c in cs {
        d = meet_d(d, esc_one(eval_n(c, a, h)));
    }
    d
}
fn ceils_dec_p(cs: &[LCeil], gid: &str, a: &Act, h: &Hist) -> Dec {
    let mut d = ALLOW;
    for c in cs {
        let x = if applies_l(&c.sel, gid, &a.verb) { bound_stat(&c.core, &c.sel, a, h) } else { ALLOW };
        d = meet_d(d, x);
    }
    d
}
fn pred_match(p: &LPred, dg: &Delegation, a: &Act, h: &Hist) -> Tri {
    and_k(b2t(a.verb == p.verb && deleg_ok(dg, &p.gid, a)), and_k(b2t(res_ok(&p.res, &a.res)), eval_n(&p.cond, a, h)))
}
pub fn pred_dec(p: &LPred, ceils: &[LCeil], dg: &Delegation, a: &Act, h: &Hist) -> Dec {
    meet_d(tri_dec(pred_match(p, dg, a, h)), ceils_dec_p(ceils, &p.gid, a, h))
}
fn preds_dec_p(ps: &[LPred], ceils: &[LCeil], dg: &Delegation, a: &Act, h: &Hist) -> Dec {
    let mut d = DENY;
    for p in ps {
        d = join_d(d, pred_dec(p, ceils, dg, a, h));
    }
    d
}
pub fn prohs_dec(p: &Pol, a: &Act, h: &Hist) -> Dec {
    proh_dec_p(&p.prohs, a, h)
}
pub fn escs_dec(p: &Pol, a: &Act, h: &Hist) -> Dec {
    esc_dec_p(&p.escs, a, h)
}
/// `D_P`: the decision of a lowered policy.
pub fn dp(p: &Pol, a: &Act, h: &Hist) -> Dec {
    meet_d(
        validity_dec(&p.validity, &p.deleg, a, h),
        meet_d(proh_dec_p(&p.prohs, a, h), meet_d(esc_dec_p(&p.escs, a, h), preds_dec_p(&p.preds, &p.ceils, &p.deleg, a, h))),
    )
}

// ---- lowering
pub fn lower(ont: &Ontology, g: &Goal) -> Pol {
    Pol {
        preds: g.grants.iter().map(|x| LPred { gid: x.gid.clone(), verb: x.verb.clone(), res: resolve_sel(ont, &x.res), cond: nnf(&x.cond, true) }).collect(),
        prohs: g
            .prohibits
            .iter()
            .map(|x| LProh { pid: x.pid.clone(), verbs: proh_verbs(ont, &x.target), res: resolve_sel(ont, &x.res), cond: nnf(&x.cond, true) })
            .collect(),
        ceils: g.bounds.iter().map(|b| LCeil { bid: b.bid.clone(), sel: resolve_bsel(ont, &b.sel), core: b.core.clone() }).collect(),
        escs: g.escalate_on.iter().map(|c| nnf(c, true)).collect(),
        validity: g.validity,
        deleg: g.deleg.clone(),
    }
}
fn depends_on(hs: &[Hole], gid: &str) -> bool {
    hs.iter().any(|h| h.global || h.affects.iter().any(|x| x == gid))
}
/// Drop every grant that depends on a hole; the other clauses stay.
pub fn strip(g: &Goal) -> Goal {
    let mut s = g.clone();
    s.grants = g.grants.iter().filter(|x| !depends_on(&g.holes, &x.gid)).cloned().collect();
    s.holes = vec![];
    s
}
pub fn type_reasons(ont: &Ontology, g: &Goal) -> Vec<String> {
    let mut rs: Vec<String> = Vec::new();
    let mut push = |bad: bool, r: &str| {
        if bad {
            rs.push(r.to_string());
        }
    };
    push(!sorted4(g), "not_canonical_order");
    push(!g.grants.iter().all(|x| grant_ok(ont, g, x)), "ill_typed_grant");
    push(!g.prohibits.iter().all(|x| prohibit_ok(ont, x)), "ill_typed_prohibit");
    push(!g.bounds.iter().all(|x| bound_ok(ont, g, x)), "ill_typed_bound");
    push(!escs_typed(ont, g), "ill_typed_escalation");
    push(!validity_ok(&g.validity, &g.deleg, g), "bad_validity_or_delegation");
    push(!g.holes.iter().all(|x| hole_ok(g, x)), "bad_hole");
    rs
}
/// C: ill-typed goals are rejected with reasons; a goal with holes compiles to its most restrictive completion.
pub fn compile(ont: &Ontology, g: &Goal) -> CResult {
    let rs = type_reasons(ont, g);
    if !rs.is_empty() {
        CResult::Escalate(rs)
    } else {
        CResult::Compiled(lower(ont, &strip(g)))
    }
}

// ---- witnesses (G-T3)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wit {
    pub gid: String,
    pub bids: Vec<String>,
}
fn applicable(cs: &[LCeil], gid: &str, verb: &str) -> Vec<String> {
    cs.iter().filter(|c| applies_l(&c.sel, gid, verb)).map(|c| c.bid.clone()).collect()
}
/// The decision together with the witness of an Allow (the first grant whose own decision is Allow).
pub fn decide_w(p: &Pol, a: &Act, h: &Hist) -> (Dec, Wit) {
    let none = Wit { gid: String::new(), bids: vec![] };
    let d = dp(p, a, h);
    if d != ALLOW {
        return (d, none);
    }
    match p.preds.iter().find(|pr| pred_dec(pr, &p.ceils, &p.deleg, a, h) == ALLOW) {
        Some(pr) => (ALLOW, Wit { gid: pr.gid.clone(), bids: applicable(&p.ceils, &pr.gid, &a.verb) }),
        None => (DENY, none),
    }
}
/// The checker: re-evaluates ONE grant and the gates, never the whole policy.
pub fn verify_witness(p: &Pol, a: &Act, h: &Hist, w: &Wit) -> bool {
    validity_dec(&p.validity, &p.deleg, a, h) == ALLOW
        && proh_dec_p(&p.prohs, a, h) == ALLOW
        && esc_dec_p(&p.escs, a, h) == ALLOW
        && p.preds.iter().any(|pr| pr.gid == w.gid && pred_dec(pr, &p.ceils, &p.deleg, a, h) == ALLOW)
        && w.bids == applicable(&p.ceils, &w.gid, &a.verb)
}
