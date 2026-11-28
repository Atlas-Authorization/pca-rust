//! Principal review and signing for a Goal IR (`review.ts`).
//!
//! PolicyCard: a deterministic, template-only rendering of the WHOLE Goal from the same phrase table as the plain text card, with
//! exact numbers. Lossless-or-refuse: a clause that cannot be rendered and digested makes the card fail; the card is never
//! truncated. The reviewer-fatigue limits are hard caps that REFUSE a goal or diff that is too large to read; callers may only
//! tighten them. Semantic diff: clause-level, widenings first; anything not PROVEN narrower counts as a widening. GoalApproval: a
//! pinned reviewer signs the digests of goal, compiled policy, card, ontology, tests, instruction and model set;
//! [`load_approved_goal`] trusts nothing the submission claims about itself (recomputes every digest, recompiles, re-renders,
//! re-runs the confirmed examples) and never fails.
use super::examples::{expected_decision, tests_digest};
use super::*;
use crate::agent::KeyPair;
use crate::goal::card::{
    bound_line, cond as cond_text, delegation_line, escalate_line, grant_line, hole_line, prohibit_line, quantity as quantity_text, res as res_text,
    validity_line,
};
use crate::goal::compiler::{compile_goal, decide_goal, policy_digest};
use crate::goal::digests::{goal_digest, model_set_digest, nl_digest};
use crate::goal::js::{safe_int, truthy};
use crate::goal::sign::{sign_goal_artifact, verify_goal_artifact};
use serde_json::{json, Map};

/// Why a goal or diff cannot be reviewed (`Review`, with the reference's code) or an unexpected failure (`Other`).
#[derive(Debug, Clone)]
pub enum RErr {
    Review(String, String),
    Other(String),
}
impl RErr {
    pub fn code(&self) -> &str {
        match self {
            RErr::Review(c, _) => c,
            RErr::Other(_) => "error",
        }
    }
}
impl std::fmt::Display for RErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RErr::Review(c, d) => write!(f, "goal review: {c}: {d}"),
            RErr::Other(m) => write!(f, "{m}"),
        }
    }
}
impl From<String> for RErr {
    fn from(s: String) -> Self {
        RErr::Other(s)
    }
}
impl From<&str> for RErr {
    fn from(s: &str) -> Self {
        RErr::Other(s.to_string())
    }
}
pub type RRes<T> = Result<T, RErr>;
fn rev_err<T>(code: &str, detail: String) -> RRes<T> {
    Err(RErr::Review(code.to_string(), detail))
}

/// The compiler and decision entry points this flow needs (injected). Pure and total.
pub struct ReviewKernel {
    pub compile: Box<dyn Fn(&Value, &Value) -> Res<Value>>,
    pub policy_digest: Box<dyn Fn(&Value) -> Res<String>>,
    /// Error-level analyzer findings over the compiled policy; any finding refuses.
    pub analyze: Option<Box<dyn Fn(&Value) -> Res<Vec<String>>>>,
    /// The decision for `(goal, ontology, act, hist)` (needed to re-run the confirmed examples).
    pub decide: Option<Box<dyn Fn(&Value, &Value, &Value, &Value) -> Res<String>>>,
    /// Actions allowed by `next` and not by `prev`: `{witnesses, complete}`.
    pub newly_allowed: Option<Box<dyn Fn(&Value, &Value, &Value, usize) -> Res<Value>>>,
}
/// The extracted, machine-proved compiler behind the typed bridge.
pub fn proved_kernel() -> ReviewKernel {
    ReviewKernel {
        compile: Box::new(|g, o| compile_goal(g, o)),
        policy_digest: Box::new(|p| Ok(policy_digest(p))),
        analyze: None,
        decide: Some(Box::new(|g, o, a, h| decide_goal(g, o, a, h).map(|d| d.to_string()))),
        newly_allowed: None,
    }
}

// ---- limits (reviewer fatigue) --------------------------------------------------------------------------------------------------

pub const REVIEW_LIMITS: [(&str, i64); 10] = [
    ("max_grants", 32),
    ("max_prohibits", 64),
    ("max_bounds", 32),
    ("max_escalate_on", 32),
    ("max_examples", 40),
    ("max_card_lines", 200),
    ("max_card_bytes", 24_576),
    ("max_diff_changes", 60),
    ("max_diff_widenings", 12),
    ("max_witnesses", 20),
];
#[derive(Debug, Clone)]
pub struct Limits(pub Vec<(&'static str, i64)>);
impl Limits {
    pub fn get(&self, k: &str) -> i64 {
        self.0.iter().find(|(n, _)| *n == k).map_or(0, |x| x.1)
    }
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        for (k, v) in &self.0 {
            m.insert(k.to_string(), json!(v));
        }
        Value::Object(m)
    }
}
/// Caller overrides may only TIGHTEN a limit (a larger number is ignored).
pub fn effective_limits(o: &Value) -> Limits {
    let mut out: Vec<(&'static str, i64)> = REVIEW_LIMITS.to_vec();
    if o.is_object() {
        for e in out.iter_mut() {
            if let Some(v) = safe_int(o.get(e.0)) {
                if v >= 0 && v < e.1 {
                    e.1 = v;
                }
            }
        }
    }
    Limits(out)
}

const D_CARD: &str = "atlas-pca/policy-card/v1";
const D_CLAUSE: &str = "atlas-pca/goal-clause/v1";
pub const GOAL_APPROVAL_KIND: &str = "goal-approval";
pub const MAX_GOAL_APPROVAL_TTL_MS: i64 = 24 * 3_600_000;
const DEFAULT_TTL_MS: i64 = 3_600_000;

fn json_of(v: &Value) -> RRes<String> {
    crate::canonicalize_strict(v).or_else(|_| rev_err("unrenderable", "a clause has no canonical form (float, undefined or cycle)".to_string()))
}
/// `jsonOf(x)` of a member that may be absent (`undefined` has no canonical form).
fn jo(v: Option<&Value>) -> RRes<String> {
    match v {
        Some(x) => json_of(x),
        None => rev_err("unrenderable", "a clause has no canonical form (float, undefined or cycle)".to_string()),
    }
}
fn line(id: &Value, kind: &str, text: String, clause: &Value, severity: &str) -> RRes<Value> {
    let cd = hc(&json!({"d": D_CLAUSE, "kind": kind, "clause": clause}))?;
    Ok(json!({"id": id, "kind": kind, "severity": severity, "text": text, "clause_digest": cd}))
}
/// Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped.
fn safe_text(f: impl FnOnce() -> Res<String>, clause: &Value) -> RRes<String> {
    match f() {
        Ok(t) if !t.contains("undefined") => Ok(t),
        _ => json_of(clause),
    }
}
fn go(goal: &Value) -> RRes<String> {
    goal_digest(goal).or_else(|_| rev_err("unrenderable", "the Goal has no canonical form (float, undefined or cycle)".to_string()))
}

/// Render the card. Deterministic, no model, no locale. Errors (`Review`): `holes` (a draft is not reviewable for signing),
/// `wildcard_unacknowledged`, `card_too_large` (a fatigue cap), `unrenderable`. `opts`: `{limits?, allowHoles?}` (allowHoles renders a
/// DRAFT for display).
pub fn render_policy_card(goal: &Value, tests: &[Value], opts: &Value) -> RRes<Value> {
    let l = effective_limits(g(opts, "limits"));
    let big = |what: &str, n: usize, max: i64| -> RRes<()> {
        if n as i64 > max {
            rev_err("card_too_large", format!("{n} {what} exceed the cap of {max}: split the goal into smaller goals"))
        } else {
            Ok(())
        }
    };
    let arrs = ["grants", "prohibits", "bounds", "escalateOn", "holes"].iter().all(|k| goal.get(*k).is_some_and(Value::is_array));
    if !(goal.is_object() && arrs && g(goal, "validity").is_object() && g(goal, "deleg").is_object()) {
        return rev_err("unrenderable", "not a Goal IR".to_string());
    }
    let (grants, prohibits, bounds, esc, holes) =
        (arr(g(goal, "grants")), arr(g(goal, "prohibits")), arr(g(goal, "bounds")), arr(g(goal, "escalateOn")), arr(g(goal, "holes")));
    big("grants", grants.len(), l.get("max_grants"))?;
    big("prohibitions", prohibits.len(), l.get("max_prohibits"))?;
    big("bounds", bounds.len(), l.get("max_bounds"))?;
    big("escalation triggers", esc.len(), l.get("max_escalate_on"))?;
    big("boundary examples", tests.len(), l.get("max_examples"))?;
    big("card lines", 3 + grants.len() + prohibits.len() + bounds.len() + esc.len() + holes.len() + tests.len(), l.get("max_card_lines"))?;
    if !holes.is_empty() && !truthy(opts.get("allowHoles")) {
        return rev_err("holes", format!("{} unresolved question(s): a goal with holes is a draft and cannot be signed", holes.len()));
    }
    let ack: &[Value] = arr(g(goal, "wildcardAck"));
    let mut lines: Vec<Value> = vec![];
    let principal = jo(goal.get("principal"))?;
    lines.push(line(
        &json!("principal"),
        "meta",
        format!("Acting for principal {principal}. Nothing outside this card is allowed (default deny)."),
        g(goal, "principal"),
        "info",
    )?);
    for gr in grants {
        let wild = st(g(g(gr, "res"), "k")) == "any";
        if wild && !includes_v(ack, g(gr, "gid")) {
            return rev_err("wildcard_unacknowledged", format!("grant {} allows ANY resource without a wildcard acknowledgement", jo(gr.get("gid"))?));
        }
        let text = safe_text(|| Ok(format!("{}.{}", grant_line(Some(gr))?, if wild { " WILDCARD acknowledged by the principal." } else { "" })), gr)?;
        lines.push(line(g(gr, "gid"), "grant", text, gr, if wild { "red" } else { "info" })?);
    }
    for p in prohibits {
        let text = safe_text(|| Ok(format!("{}.", prohibit_line(Some(p))?)), p)?;
        lines.push(line(g(p, "pid"), "prohibit", text, p, if st(g(g(p, "res"), "k")) == "any" { "red" } else { "info" })?);
    }
    for b in bounds {
        let text = safe_text(|| Ok(format!("{}.", bound_line(Some(b))?)), b)?;
        lines.push(line(g(b, "bid"), "bound", text, b, "info")?);
    }
    let (validity, deleg) = (g(goal, "validity"), g(goal, "deleg"));
    lines.push(line(&json!("validity"), "validity", safe_text(|| Ok(format!("{}.", validity_line(Some(validity))?)), validity)?, validity, "info")?);
    lines.push(line(
        &json!("delegation"),
        "delegation",
        safe_text(|| Ok(format!("{}.", delegation_line(Some(deleg))?)), deleg)?,
        deleg,
        if truthy(deleg.get("narrowOnly")) { "info" } else { "red" },
    )?);
    for (i, c) in esc.iter().enumerate() {
        lines.push(line(&json!(format!("escalate_on[{i}]")), "escalate", safe_text(|| Ok(format!("{}.", escalate_line(Some(c))?)), c)?, c, "info")?);
    }
    for (i, h) in holes.iter().enumerate() {
        let text = safe_text(|| Ok(format!("{}. Everything depending on it is dropped.", hole_line(Some(h))?)), h)?;
        lines.push(line(&json!(format!("hole[{i}]")), "hole", text, h, "red")?);
    }
    for t in tests {
        let act = match t.get("act") {
            Some(a) if !a.is_null() => a,
            _ => return Err(RErr::Other("Cannot read properties of undefined (reading 'verb')".into())),
        };
        let adms = match t.get("hist") {
            Some(h) if !h.is_null() => g(h, "adms"),
            _ => return Err(RErr::Other("Cannot read properties of undefined (reading 'adms')".into())),
        };
        let n = match adms {
            Value::Array(a) => a.len(),
            Value::String(s) => s.encode_utf16().count(),
            _ => return Err(RErr::Other("Cannot read properties of undefined (reading 'length')".into())),
        };
        let after = if n > 0 { format!(" after {n} earlier admitted action(s)") } else { String::new() };
        let ans = match st(g(t, "answer")) {
            "ask" => "ASKED about",
            "allow" => "ALLOWED",
            _ => "DENIED",
        };
        let text = format!("EXAMPLE you confirmed: {} on {} with {}{after} must be {ans}.", jo(act.get("verb"))?, jo(act.get("res"))?, jo(act.get("params"))?);
        lines.push(line(&json!(format!("example:{}", js_s(g(t, "id")))), "example", text, t, "info")?);
    }
    big("card lines", lines.len(), l.get("max_card_lines"))?;
    let mut card = Map::new();
    card.insert("v".into(), json!(1));
    card.insert("goal_digest".into(), json!(go(goal)?));
    for (k, from) in [("ontology_digest", "ontDigest"), ("nl_digest", "nlDigest"), ("principal", "principal")] {
        if let Some(v) = goal.get(from) {
            card.insert(k.into(), v.clone());
        }
    }
    card.insert("lines".into(), Value::Array(lines));
    let card = Value::Object(card);
    let bytes = crate::canonicalize_strict(&card).map_err(RErr::Other)?.len();
    big("bytes of card", bytes, l.get("max_card_bytes"))?;
    Ok(card)
}

pub fn card_digest(card: &Value) -> Res<String> {
    hc(&json!({"d": D_CARD, "card": card}))
}
/// Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`.
pub fn card_to_text(card: &Value) -> Res<String> {
    Ok(req_arr(g(card, "lines"))?
        .iter()
        .map(|l| format!("{}{}", if st(g(l, "severity")) == "red" { "!! " } else { "   " }, js_s(g(l, "text"))))
        .collect::<Vec<_>>()
        .join("\n"))
}

// ---- semantic diff ----------------------------------------------------------------------------------------------------------------

fn same(a: &Value, b: &Value) -> RRes<bool> {
    Ok(json_of(a)? == json_of(b)?)
}
fn same_o(a: Option<&Value>, b: Option<&Value>) -> RRes<bool> {
    Ok(jo(a)? == jo(b)?)
}
fn conjuncts(c: &Value) -> Vec<Value> {
    match st(g(c, "k")) {
        "and" => conjuncts(g(c, "a")).into_iter().chain(conjuncts(g(c, "b"))).collect(),
        "true" => vec![],
        _ => vec![c.clone()],
    }
}
/// new.cond is old.cond AND more (or equal): provably no wider.
fn where_no_wider(old_w: &Value, new_w: &Value) -> RRes<bool> {
    let mut have: Vec<String> = vec![];
    for c in conjuncts(new_w) {
        have.push(json_of(&c)?);
    }
    for c in conjuncts(old_w) {
        if !have.contains(&json_of(&c)?) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn grant_dir(o: &Value, n: &Value) -> RRes<&'static str> {
    if same(o, n)? {
        return Ok("neutral");
    }
    Ok(if seq_eq(g(o, "verb"), g(n, "verb")) && same_o(o.get("res"), n.get("res"))? && where_no_wider(g(o, "cond"), g(n, "cond"))? {
        "narrow"
    } else {
        "unknown"
    })
}
fn prohibit_dir(o: &Value, n: &Value) -> RRes<&'static str> {
    if same(o, n)? {
        return Ok("neutral");
    }
    // A prohibition that triggers on MORE (old.cond is a conjunction containing new.cond) is a narrowing of the allow set.
    Ok(if same_o(o.get("target"), n.get("target"))? && same_o(o.get("res"), n.get("res"))? && where_no_wider(g(n, "cond"), g(o, "cond"))? {
        "narrow"
    } else {
        "unknown"
    })
}
fn bound_dir(o: &Value, n: &Value) -> RRes<&'static str> {
    if same(o, n)? {
        return Ok("neutral");
    }
    let rest = |b: &Value| -> Value {
        let mut m = b.as_object().cloned().unwrap_or_default();
        m.insert("cap".into(), Value::Null);
        Value::Object(m)
    };
    if !same(&rest(o), &rest(n))? || !same_o(g(o, "cap").get("u"), g(n, "cap").get("u"))? {
        return Ok("unknown");
    }
    let (on, nn) = (nm(g(g(o, "cap"), "n")), nm(g(g(n, "cap"), "n")));
    Ok(if nn < on {
        "narrow"
    } else if nn > on {
        "widen"
    } else if nn == on {
        "neutral"
    } else {
        "unknown"
    })
}
/// maxIdle 0 means "no idle limit": the widest.
fn idle(x: &Value) -> f64 {
    if nm(x) == 0.0 {
        f64::INFINITY
    } else {
        nm(x)
    }
}
fn validity_dir(o: &Value, n: &Value) -> RRes<&'static str> {
    if same(o, n)? {
        return Ok("neutral");
    }
    let (nb, na, ni) = (nm(g(n, "notBefore")), nm(g(n, "notAfter")), idle(g(n, "maxIdle")));
    let (ob, oa, oi) = (nm(g(o, "notBefore")), nm(g(o, "notAfter")), idle(g(o, "maxIdle")));
    let nar = nb >= ob && na <= oa && ni <= oi;
    let wid = nb <= ob && na >= oa && ni >= oi;
    Ok(if nar {
        "narrow"
    } else if wid {
        "widen"
    } else {
        "unknown"
    })
}
fn delegation_dir(o: &Value, n: &Value) -> RRes<&'static str> {
    if same(o, n)? {
        return Ok("neutral");
    }
    let (to, tn) = (arr(g(o, "mayTouch")), arr(g(n, "mayTouch")));
    let sub = tn.iter().all(|x| includes_v(to, x));
    let sup = to.iter().all(|x| includes_v(tn, x));
    let (on, nn) = (truthy(o.get("narrowOnly")), truthy(n.get("narrowOnly")));
    let nar = nm(g(n, "maxDepth")) <= nm(g(o, "maxDepth")) && sub && (nn || !on);
    let wid = nm(g(n, "maxDepth")) >= nm(g(o, "maxDepth")) && sup && (on || !nn);
    Ok(if nar {
        "narrow"
    } else if wid {
        "widen"
    } else {
        "unknown"
    })
}

type Keyed = Vec<(Value, Value)>;
fn keyed(xs: &Value, k: &str) -> Res<Keyed> {
    Ok(req_arr(xs)?.iter().map(|x| (g(x, k).clone(), x.clone())).collect())
}
fn pairs(
    prev: &Keyed,
    next: &Keyed,
    kind: &str,
    added: &str,
    removed: &str,
    changed: &dyn Fn(&Value, &Value) -> RRes<&'static str>,
    text: &dyn Fn(&Value, &Value) -> RRes<String>,
) -> RRes<Vec<Value>> {
    let mut out = vec![];
    let find = |ks: &Keyed, id: &Value| -> Option<Value> { ks.iter().rev().find(|(k, _)| seq_eq(k, id)).map(|(_, v)| v.clone()) };
    for (id, v) in next {
        match find(prev, id) {
            None => out.push(json!({"change": "added", "kind": kind, "id": id, "direction": added, "text": format!("ADDED {}", text(id, v)?)})),
            Some(o) => {
                if !same(&o, v)? {
                    out.push(json!({"change": "changed", "kind": kind, "id": id, "direction": changed(&o, v)?, "text": format!("CHANGED {} (was: {})", text(id, v)?, text(id, &o)?)}));
                }
            }
        }
    }
    for (id, v) in prev {
        if find(next, id).is_none() {
            out.push(json!({"change": "removed", "kind": kind, "id": id, "direction": removed, "text": format!("REMOVED {}", text(id, v)?)}));
        }
    }
    Ok(out)
}

/// Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Errors
/// (`Review`) `diff_too_large` / `too_many_widenings` past the fatigue caps: a diff a human cannot read is not offered as one.
/// `opts`: `{limits?, ontology?}`; only a kernel with `newly_allowed` lists the newly allowed actions.
pub fn diff_goals(prev: &Value, next: &Value, kernel: Option<&ReviewKernel>, opts: &Value) -> RRes<Value> {
    let l = effective_limits(g(opts, "limits"));
    let rt = |v: &Value| res_text(Some(v));
    let gl = |id: &Value, gr: &Value| -> RRes<String> {
        Ok(format!("grant {}: {} on {} when {}", jo(Some(id))?, jo(gr.get("verb"))?, rt(g(gr, "res"))?, cond_text(Some(g(gr, "cond")))?))
    };
    let pl = |id: &Value, p: &Value| -> RRes<String> {
        let t = g(p, "target");
        let tgt = if st(g(t, "k")) == "verb" { jo(t.get("verb"))? } else { format!("effect class {}", jo(t.get("cls"))?) };
        Ok(format!("prohibition {}: {tgt} on {} when {}", jo(Some(id))?, rt(g(p, "res"))?, cond_text(Some(g(p, "cond")))?))
    };
    let bl =
        |id: &Value, b: &Value| -> RRes<String> { Ok(format!("bound {}: {} ({})", jo(Some(id))?, bound_line(Some(b))?, quantity_text(Some(g(b, "cap")))?)) };
    let el = |_id: &Value, c: &Value| -> RRes<String> { Ok(format!("escalation when {}", cond_text(Some(c))?)) };
    let mut changes: Vec<Value> = vec![];
    changes.extend(pairs(&keyed(g(prev, "grants"), "gid")?, &keyed(g(next, "grants"), "gid")?, "grant", "widen", "narrow", &grant_dir, &gl)?);
    changes.extend(pairs(&keyed(g(prev, "prohibits"), "pid")?, &keyed(g(next, "prohibits"), "pid")?, "prohibit", "narrow", "widen", &prohibit_dir, &pl)?);
    changes.extend(pairs(&keyed(g(prev, "bounds"), "bid")?, &keyed(g(next, "bounds"), "bid")?, "bound", "narrow", "widen", &bound_dir, &bl)?);
    let esc = |x: &Value| -> RRes<Keyed> {
        let mut out = vec![];
        for c in req_arr(g(x, "escalateOn")).map_err(RErr::Other)? {
            out.push((Value::String(json_of(c)?), c.clone()));
        }
        Ok(out)
    };
    changes.extend(pairs(&esc(prev)?, &esc(next)?, "escalate", "narrow", "widen", &|_, _| Ok("unknown"), &el)?);
    let (pv, nv) = (g(prev, "validity"), g(next, "validity"));
    if !same_o(prev.get("validity"), next.get("validity"))? {
        changes.push(json!({"change": "changed", "kind": "validity", "id": "validity", "direction": validity_dir(pv, nv)?,
            "text": format!("CHANGED validity: {} (was: {})", json_of(nv)?, json_of(pv)?)}));
    }
    let (pd, nd) = (g(prev, "deleg"), g(next, "deleg"));
    if !same_o(prev.get("deleg"), next.get("deleg"))? {
        changes.push(json!({"change": "changed", "kind": "delegation", "id": "delegation", "direction": delegation_dir(pd, nd)?,
            "text": format!("CHANGED delegation: {} (was: {})", json_of(nd)?, json_of(pd)?)}));
    }
    // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
    if !seq_eq(g(prev, "principal"), g(next, "principal")) {
        changes.push(json!({"change": "changed", "kind": "meta", "id": "principal", "direction": "unknown",
            "text": format!("CHANGED principal: {} (was: {})", jo(next.get("principal"))?, jo(prev.get("principal"))?)}));
    }
    if !seq_eq(g(prev, "ontDigest"), g(next, "ontDigest")) {
        changes.push(json!({"change": "changed", "kind": "meta", "id": "ontology", "direction": "unknown",
            "text": format!("CHANGED ontology: every term now means what the new vocabulary says (was {}, now {})", jo(prev.get("ontDigest"))?, jo(next.get("ontDigest"))?)}));
    }
    if !same_o(prev.get("wildcardAck"), next.get("wildcardAck"))? {
        changes.push(json!({"change": "changed", "kind": "meta", "id": "wildcard_ack", "direction": "unknown",
            "text": format!("CHANGED wildcard acknowledgements: {} (was: {})", jo(next.get("wildcardAck"))?, jo(prev.get("wildcardAck"))?)}));
    }
    if !seq_eq(g(prev, "nlDigest"), g(next, "nlDigest")) {
        changes.push(json!({"change": "changed", "kind": "meta", "id": "instruction", "direction": "neutral", "text": "CHANGED the instruction text the goal was interpreted from"}));
    }
    let is_wide = |c: &Value| matches!(st(g(c, "direction")), "widen" | "unknown");
    let widenings = changes.iter().filter(|c| is_wide(*c)).count();
    if changes.len() as i64 > l.get("max_diff_changes") {
        return rev_err(
            "diff_too_large",
            format!("{} changes exceed the cap of {}: review the new goal as a whole instead", changes.len(), l.get("max_diff_changes")),
        );
    }
    if widenings as i64 > l.get("max_diff_widenings") {
        return rev_err("too_many_widenings", format!("{widenings} widenings exceed the cap of {} per review", l.get("max_diff_widenings")));
    }
    let max_w = l.get("max_witnesses").max(0) as usize;
    let ont = g(opts, "ontology");
    let na = match (truthy(opts.get("ontology")), kernel.and_then(|k| k.newly_allowed.as_ref())) {
        (true, Some(f)) => Some(f(prev, next, ont, max_w)?),
        _ => None,
    };
    let (new_allowed, complete) = match &na {
        Some(n) => {
            let w = arr(g(n, "witnesses"));
            (w.iter().take(max_w).cloned().collect::<Vec<_>>(), truthy(n.get("complete")) && w.len() <= max_w)
        }
        None => (vec![], false),
    };
    let mut ordered: Vec<Value> = changes.iter().filter(|c| is_wide(*c)).cloned().collect();
    ordered.extend(changes.iter().filter(|c| !is_wide(*c)).cloned());
    Ok(json!({"v": 1, "from_goal_digest": go(prev)?, "to_goal_digest": go(next)?, "newly_allowed": new_allowed, "newly_allowed_complete": complete,
        "changes": ordered, "widenings": widenings}))
}

pub fn diff_to_text(d: &Value) -> RRes<String> {
    let mut head: Vec<String> = vec![];
    for w in arr(g(d, "newly_allowed")) {
        head.push(format!("!! NEWLY ALLOWED: {} on {} with {}", jo(w.get("verb"))?, jo(w.get("res"))?, jo(w.get("params"))?));
    }
    if !truthy(d.get("newly_allowed_complete")) {
        head.push("!! The list of newly allowed actions is incomplete or unavailable: read every widening below.".into());
    }
    for c in req_arr(g(d, "changes"))? {
        head.push(format!("{}{}", if matches!(st(g(c, "direction")), "widen" | "unknown") { "!! " } else { "   " }, js_s(g(c, "text"))));
    }
    Ok(head.join("\n"))
}

// ---- GoalApproval -----------------------------------------------------------------------------------------------------------------

pub const GOAL_APPROVAL_SIGNED_FIELDS: [&str; 11] = [
    "v",
    "goal_digest",
    "policy_digest",
    "card_digest",
    "ontology_digest",
    "tests_digest",
    "nl_digest",
    "model_set_digest",
    "reviewer",
    "approved_at",
    "expires_at",
];
const FIELD_REASON: [(&str, &str); 7] = [
    ("goal_digest", "goal_digest_mismatch"),
    ("policy_digest", "policy_digest_mismatch"),
    ("ontology_digest", "ontology_mismatch"),
    ("tests_digest", "tests_digest_mismatch"),
    ("nl_digest", "nl_digest_mismatch"),
    ("model_set_digest", "model_set_digest_mismatch"),
    ("card_digest", "card_digest_mismatch"),
];

struct Derived {
    policy: Value,
    digests: Value,
}
fn derive(sub: &Value, kernel: &ReviewKernel, limits: Option<&Value>) -> Result<Derived, String> {
    let goal = g(sub, "goal");
    let ms_ok = sub.get("model_set").and_then(Value::as_array).is_some_and(|a| a.iter().all(Value::is_string));
    if !(sub.is_object() && goal.is_object() && g(sub, "ontology").is_object() && g(sub, "instruction").is_string() && ms_ok)
        || sub.get("tests").is_some_and(|t| !t.is_array())
    {
        return Err("malformed_submission".to_string());
    }
    let tests: Vec<Value> = arr(g(sub, "tests")).to_vec();
    let opts = match limits {
        Some(l) => json!({"limits": l}),
        None => json!({}),
    };
    let card = match render_policy_card(goal, &tests, &opts) {
        Ok(c) => c,
        Err(RErr::Review(code, _)) => return Err(code),
        Err(_) => return Err("malformed_goal".to_string()),
    };
    let gd = goal_digest(goal).map_err(|_| "malformed_goal".to_string())?;
    let nl = nl_digest(g(sub, "instruction")).map_err(|_| "malformed_goal".to_string())?;
    let ts = tests_digest(&tests).map_err(|_| "malformed_goal".to_string())?;
    let ms = model_set_digest(&strs(arr(g(sub, "model_set")))).map_err(|_| "malformed_goal".to_string())?;
    if !seq_eq(g(goal, "nlDigest"), &Value::String(nl.clone())) {
        return Err("instruction_mismatch".to_string());
    }
    let ont = g(sub, "ontology");
    let compiled = (kernel.compile)(goal, ont).map_err(|_| "compile_error".to_string())?;
    if compiled["ok"] != true {
        return Err("compile_error".to_string());
    }
    let policy = g(&compiled, "policy").clone();
    let found = match &kernel.analyze {
        Some(f) => f(&policy).map_err(|_| "analyzer_error".to_string())?,
        None => vec![],
    };
    if !found.is_empty() {
        return Err("analyzer_error".to_string());
    }
    let pd = (kernel.policy_digest)(&policy).map_err(|_| "analyzer_error".to_string())?;
    if !tests.is_empty() {
        let decide = kernel.decide.as_ref().ok_or("tests_unverifiable".to_string())?;
        // Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
        for t in &tests {
            let ont2 = if truthy(t.get("rels")) {
                let mut m = ont.as_object().cloned().unwrap_or_default();
                m.insert("rels".into(), g(t, "rels").clone());
                Value::Object(m)
            } else {
                ont.clone()
            };
            let got = decide(goal, &ont2, g(t, "act"), g(t, "hist")).map_err(|_| "tests_unverifiable".to_string())?;
            if got != expected_decision(st(g(t, "answer"))) {
                return Err("tests_contradicted".to_string());
            }
        }
    }
    let cd = card_digest(&card).map_err(|_| "malformed_goal".to_string())?;
    Ok(Derived {
        policy,
        digests: json!({"goal_digest": gd, "policy_digest": pd, "card_digest": cd, "ontology_digest": g(goal, "ontDigest"), "tests_digest": ts, "nl_digest": nl, "model_set_digest": ms}),
    })
}

/// Options of [`approve_goal`]: the kernel (required), `now` (default: the clock), `ttl_ms` (default one hour), `limits`, and the
/// previously approved `base` goal the new one is diffed against (the diff caps then apply).
pub struct ApproveOpts<'a> {
    pub kernel: &'a ReviewKernel,
    pub now: Option<&'a Value>,
    pub ttl_ms: Option<&'a Value>,
    pub limits: Option<&'a Value>,
    pub base: Option<&'a Value>,
}
fn clock_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

/// The human step: sign the exact goal. Re-derives everything the loader will; fails when the goal is not signable (holes, wildcard
/// without ack, card or diff over the fatigue caps, compile or analyzer failure, a test the compiled policy contradicts, an
/// instruction that does not match `nlDigest`).
pub fn approve_goal(sub: &Value, reviewer: &KeyPair, o: &ApproveOpts) -> Res<Value> {
    let now = match o.now.filter(|v| !v.is_null()) {
        Some(v) => safe_int(Some(v)),
        None => Some(clock_ms()),
    };
    let ttl = match o.ttl_ms.filter(|v| !v.is_null()) {
        Some(v) => safe_int(Some(v)),
        None => Some(DEFAULT_TTL_MS),
    };
    let (now, ttl) = match (now, ttl) {
        (Some(n), Some(t)) if t > 0 && t <= MAX_GOAL_APPROVAL_TTL_MS => (n, t),
        _ => return Err("approveGoal: invalid time or ttl".into()),
    };
    let d = derive(sub, o.kernel, o.limits).map_err(|r| format!("approveGoal: {r}"))?;
    if let Some(base) = o.base {
        let opts = match o.limits {
            Some(l) => json!({"limits": l}),
            None => json!({}),
        };
        diff_goals(base, g(sub, "goal"), None, &opts).map_err(|e| e.to_string())?;
    }
    let mut body = d.digests.as_object().cloned().unwrap_or_default();
    body.insert("v".into(), json!(1));
    body.insert("reviewer".into(), json!(reviewer.public));
    body.insert("approved_at".into(), json!(now));
    body.insert("expires_at".into(), json!(now + ttl));
    sign_goal_artifact(GOAL_APPROVAL_KIND, &Value::Object(body), reviewer)
}

fn fail(reason: &str) -> Value {
    json!({"ok": false, "reason": reason})
}

/// Options of [`load_approved_goal`]: the kernel (required), the pinned `reviewers` (`"pk"` or `{pk, pq_pk?}`), an optional expected
/// `ontology_digest`, `now` (default: the clock) and `limits`.
pub struct LoadOpts<'a> {
    pub kernel: &'a ReviewKernel,
    pub reviewers: &'a Value,
    pub ontology_digest: Option<&'a Value>,
    pub now: Option<&'a Value>,
    pub limits: Option<&'a Value>,
}

/// The only door from a submitted goal to an enforceable one. Recomputes the goal digest, recompiles the policy, re-renders the card
/// and re-derives the tests, instruction and model-set digests from the submission; trusts nothing the submission or the approval
/// says about itself. Never fails: `{ok: true, approved}` or `{ok: false, reason}`.
pub fn load_approved_goal(sub: &Value, approval: &Value, o: &LoadOpts) -> Value {
    let now = match o.now.filter(|v| !v.is_null()) {
        Some(v) => nm(v),
        None => clock_ms() as f64,
    };
    let reviewers = match o.reviewers.as_array() {
        Some(r) if !r.is_empty() => r,
        _ => return fail("no_reviewers_pinned"),
    };
    let a = approval;
    let sint = |k: &str| safe_int(a.get(k));
    let malformed = !a.is_object()
        || !(sint("v").is_some() && seq_eq(g(a, "v"), &json!(1)))
        || !g(a, "sig").is_string()
        || !g(a, "reviewer").is_string()
        || sint("approved_at").is_none()
        || sint("expires_at").is_none()
        || FIELD_REASON.iter().any(|(f, _)| !g(a, f).is_string());
    if malformed {
        return fail("malformed_approval");
    }
    let d = match derive(sub, o.kernel, o.limits) {
        Ok(d) => d,
        Err(r) => return fail(&r),
    };
    if let Some(od) = o.ontology_digest.filter(|v| !v.is_null()) {
        if !seq_eq(g(g(sub, "goal"), "ontDigest"), od) {
            return fail("ontology_mismatch");
        }
    }
    for (f, reason) in FIELD_REASON {
        if !seq_eq(g(a, f), g(&d.digests, f)) {
            return fail(reason);
        }
    }
    let rv = g(a, "reviewer");
    if !reviewers.iter().any(|p| seq_eq(if p.is_string() { p } else { g(p, "pk") }, rv)) {
        return fail("reviewer_not_pinned");
    }
    let (ap, ex) = (nm(g(a, "approved_at")), nm(g(a, "expires_at")));
    if ex - ap <= 0.0 || ex - ap > MAX_GOAL_APPROVAL_TTL_MS as f64 {
        return fail("ttl_too_long");
    }
    if !(now.is_finite() && ap <= now) {
        return fail("not_yet_valid");
    }
    if !(now.is_finite() && now < ex) {
        return fail("expired");
    }
    if !verify_goal_artifact(GOAL_APPROVAL_KIND, a, "reviewer", reviewers) {
        return fail("bad_signature");
    }
    let r = crate::ApprovedGoalRef { goal_digest: st(g(&d.digests, "goal_digest")).to_string(), policy_digest: st(g(&d.digests, "policy_digest")).to_string() };
    let goal_string = match crate::intent_goal_v3(&r) {
        Some(s) => s,
        None => return fail("malformed_approval"),
    };
    let rf = json!({"goal_digest": r.goal_digest, "policy_digest": r.policy_digest});
    json!({"ok": true, "approved": {"goal": g(sub, "goal"), "ontology": g(sub, "ontology"), "policy": d.policy, "ref": rf, "goal_string": goal_string,
        "intent_policy": {"approved_goal": rf}, "instruction": g(sub, "instruction"), "reviewer": rv, "expires_at": g(a, "expires_at")}})
}
