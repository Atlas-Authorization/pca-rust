//! K5 workflow (DAG) authorization: `admit_step`, `bind_promises`, `plan_root_authorized`. A pure, total port of
//! packages/pca/src/workflow.ts; replays packages/pca/conformance/workflow-vectors.json. No function panics: anything
//! unknown, malformed, unsigned, out of order or unplanned denies. Integers only: a JSON number counts as an integer only when
//! it is spelled as one (serde_json is_i64/is_u64) and |n| <= 2^53-1; `2500.0` and `1.5` are not integers, booleans are not numbers.
use crate::fresh_at::verify_body;
use crate::{decode_b64u_strict, hash_canonical_strict};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const WORKFLOW_DOMAIN: &str = "atlas-pca/workflow/v1\0";
pub const WF_RECEIPT_DOMAIN: &str = "atlas-pca/wf-receipt/v1\0";
const WF_REF: &str = "atlas-pca/workflow-ref/v1";
const WR_REF: &str = "atlas-pca/wf-receipt-ref/v1";
const VAL: &str = "atlas-pca/wf-value/v1";
const MAX_SAFE: i64 = 9_007_199_254_740_991;

const MAX_STEPS: usize = 64;
const MAX_EDGES: usize = 256;
const MAX_DEPS: usize = 16;
const MAX_LABELS: usize = 16;
const MAX_FIELDS: usize = 32;
const MAX_COST: usize = 8;

// ---- shared strict helpers (also used by readside.rs) -----------------------------------------------------------------------

/// An exact safe integer (spelled as an integer, |n| <= 2^53-1); `None` for floats, strings, booleans, null.
pub(crate) fn int(v: &Value) -> Option<i64> {
    let Value::Number(n) = v else { return None };
    let i = if let Some(i) = n.as_i64() { i } else { i64::try_from(n.as_u64()?).ok()? };
    (i.unsigned_abs() <= MAX_SAFE as u64).then_some(i)
}
pub(crate) fn uint(v: &Value) -> Option<i64> {
    int(v).filter(|n| *n >= 0)
}
pub(crate) fn is_uint(v: Option<&Value>) -> bool {
    v.and_then(uint).is_some()
}
fn class_ok(s: &str, set: impl Fn(char) -> bool, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && s.chars().all(set) && s != "__proto__"
}
pub(crate) fn is_id_str(s: &str) -> bool {
    class_ok(s, |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'), 64)
}
pub(crate) fn is_label_str(s: &str) -> bool {
    class_ok(s, |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | ':' | '-'), 64)
}
pub(crate) fn is_name_str(s: &str) -> bool {
    class_ok(s, |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'), 64)
}
fn is_unit_str(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 16 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}
fn is_id(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(is_id_str)
}
fn is_name(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(is_name_str)
}
fn is_unit(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(is_unit_str)
}
/// A non-empty string of at most `max` UTF-16 code units.
pub(crate) fn is_str(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| !s.is_empty() && s.encode_utf16().count() <= max)
}
pub(crate) fn is_b32_str(s: &str) -> bool {
    decode_b64u_strict(s, Some(32)).is_some()
}
pub(crate) fn is_b32(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(is_b32_str)
}
fn null_or(v: Option<&Value>, ok: impl Fn(Option<&Value>) -> bool) -> bool {
    matches!(v, Some(Value::Null)) || ok(v)
}
/// Strictly ascending (ASCII bytewise) list of at most `max` strings, each passing `ok`.
pub(crate) fn sorted_unique(v: Option<&Value>, ok: fn(&str) -> bool, max: usize) -> Option<Vec<String>> {
    let a = v?.as_array().filter(|a| a.len() <= max)?;
    let mut out: Vec<String> = Vec::with_capacity(a.len());
    for x in a {
        let s = x.as_str().filter(|s| ok(s))?;
        if out.last().is_some_and(|p| p.as_str() >= s) {
            return None;
        }
        out.push(s.to_string());
    }
    Some(out)
}
/// Exactly these members, no more, no fewer.
pub(crate) fn only_keys(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))
}
/// A flat map of name -> string | bool | safe integer, at most 32 entries.
pub(crate) fn is_scalar_map(v: Option<&Value>) -> bool {
    v.and_then(Value::as_object).is_some_and(|o| o.len() <= MAX_FIELDS && o.iter().all(|(k, x)| is_name_str(k) && (x.is_string() || x.is_boolean() || int(x).is_some())))
}
fn uint_map(v: Option<&Value>, max: usize) -> Option<BTreeMap<String, i64>> {
    let o = v?.as_object().filter(|o| o.len() <= max)?;
    let mut m = BTreeMap::new();
    for (k, x) in o {
        if !is_name_str(k) {
            return None;
        }
        m.insert(k.clone(), uint(x)?);
    }
    Some(m)
}
fn opt_str(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_string)
}

/// The digest of a scalar value as it appears in step receipts (domain separated, so a value digest is never a params digest).
pub fn value_digest(v: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": VAL, "v": v }))
}

// ---- validation -------------------------------------------------------------------------------------------------------------

const STEP_KEYS: [&str; 10] = ["id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost"];
const EDGE_KEYS: [&str; 6] = ["from", "to", "op", "unit", "deny_labels", "promise"];
const BODY_KEYS: [&str; 10] = ["v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget"];
const OPS: [&str; 5] = ["eq", "le", "ge", "lt", "gt"];

struct Step {
    id: String,
    verb: String,
    resource: String,
    params_digest: Option<String>,
    deps: Vec<String>,
    deny_labels: Vec<String>,
    escalate_labels: Vec<String>,
    fresh_ms: Option<i64>,
    cost: BTreeMap<String, i64>,
}
struct Edge {
    from_step: String,
    from_field: String,
    to_step: String,
    to_param: String,
    op: String,
    unit: Option<String>,
    deny_labels: Vec<String>,
    promise: Option<String>,
}
pub(crate) struct Body {
    principal: String,
    goal_digest: Option<String>,
    plan_root: Option<String>,
    issued_at: i64,
    expires_at: i64,
    steps: Vec<Step>,
    edges: Vec<Edge>,
    max_steps: i64,
    caps: BTreeMap<String, i64>,
}

fn parse_step(v: &Value) -> Option<Step> {
    let s = v.as_object().filter(|s| only_keys(s, &STEP_KEYS))?;
    if !(is_id(s.get("id")) && is_str(s.get("verb"), 128) && is_str(s.get("resource"), 512) && null_or(s.get("params_digest"), is_b32) && null_or(s.get("sink"), is_id) && null_or(s.get("fresh_ms"), is_uint)) {
        return None;
    }
    Some(Step {
        id: opt_str(s.get("id"))?,
        verb: opt_str(s.get("verb"))?,
        resource: opt_str(s.get("resource"))?,
        params_digest: opt_str(s.get("params_digest")),
        deps: sorted_unique(s.get("deps"), is_id_str, MAX_DEPS)?,
        deny_labels: sorted_unique(s.get("deny_labels"), is_label_str, MAX_LABELS)?,
        escalate_labels: sorted_unique(s.get("escalate_labels"), is_label_str, MAX_LABELS)?,
        fresh_ms: s.get("fresh_ms").and_then(uint),
        cost: uint_map(s.get("cost"), MAX_COST)?,
    })
}
fn parse_edge(v: &Value) -> Option<Edge> {
    let e = v.as_object().filter(|e| only_keys(e, &EDGE_KEYS))?;
    let f = e.get("from")?.as_object().filter(|f| only_keys(f, &["step", "field"]))?;
    let t = e.get("to")?.as_object().filter(|t| only_keys(t, &["step", "param"]))?;
    let op = e.get("op")?.as_str().filter(|o| OPS.contains(o))?;
    if !(is_id(f.get("step")) && is_name(f.get("field")) && is_id(t.get("step")) && is_name(t.get("param")) && null_or(e.get("unit"), is_unit) && null_or(e.get("promise"), is_id)) {
        return None;
    }
    Some(Edge {
        from_step: opt_str(f.get("step"))?,
        from_field: opt_str(f.get("field"))?,
        to_step: opt_str(t.get("step"))?,
        to_param: opt_str(t.get("param"))?,
        op: op.to_string(),
        unit: opt_str(e.get("unit")),
        deny_labels: sorted_unique(e.get("deny_labels"), is_label_str, MAX_LABELS)?,
        promise: opt_str(e.get("promise")),
    })
}
/// Shape of the body only (no signature, no DAG semantics): `validWorkflowBody`.
pub(crate) fn parse_body(v: &Value) -> Option<Body> {
    let b = v.as_object().filter(|b| only_keys(b, &BODY_KEYS))?;
    if b.get("v").and_then(int) != Some(1) {
        return None;
    }
    if !(is_id(b.get("id")) && is_b32(b.get("principal")) && null_or(b.get("goal_digest"), is_b32) && null_or(b.get("plan_root"), is_b32) && is_uint(b.get("issued_at")) && is_uint(b.get("expires_at"))) {
        return None;
    }
    let sa = b.get("steps")?.as_array().filter(|a| !a.is_empty() && a.len() <= MAX_STEPS)?;
    let steps = sa.iter().map(parse_step).collect::<Option<Vec<_>>>()?;
    let ea = b.get("edges")?.as_array().filter(|a| a.len() <= MAX_EDGES)?;
    let edges = ea.iter().map(parse_edge).collect::<Option<Vec<_>>>()?;
    let bg = b.get("budget")?.as_object().filter(|g| only_keys(g, &["max_steps", "caps"]))?;
    let max_steps = bg.get("max_steps").and_then(uint)?;
    let caps = uint_map(bg.get("caps"), MAX_COST)?;
    // every cost name must be capped: an uncapped cost is a budget that silently does not exist
    if !steps.iter().all(|s| s.cost.keys().all(|k| caps.contains_key(k))) {
        return None;
    }
    Some(Body {
        principal: opt_str(b.get("principal"))?,
        goal_digest: opt_str(b.get("goal_digest")),
        plan_root: opt_str(b.get("plan_root")),
        issued_at: b.get("issued_at").and_then(uint)?,
        expires_at: b.get("expires_at").and_then(uint)?,
        steps,
        edges,
        max_steps,
        caps,
    })
}

/// step id -> its transitive dependencies; `None` on a cycle. Dependencies must already be known to exist.
fn ancestors(b: &Body) -> Option<BTreeMap<String, BTreeSet<String>>> {
    fn visit(id: &str, by_id: &BTreeMap<&str, &Step>, out: &mut BTreeMap<String, BTreeSet<String>>, state: &mut BTreeMap<String, u8>) -> bool {
        match state.get(id) {
            Some(2) => return true,
            Some(_) => return false,
            None => {}
        }
        state.insert(id.to_string(), 1);
        let mut set = BTreeSet::new();
        let Some(step) = by_id.get(id) else { return false };
        for d in &step.deps {
            if !visit(d, by_id, out, state) {
                return false;
            }
            set.insert(d.clone());
            if let Some(x) = out.get(d) {
                set.extend(x.iter().cloned());
            }
        }
        out.insert(id.to_string(), set);
        state.insert(id.to_string(), 2);
        true
    }
    let by_id: BTreeMap<&str, &Step> = b.steps.iter().map(|s| (s.id.as_str(), s)).collect();
    let mut out = BTreeMap::new();
    let mut state = BTreeMap::new();
    for s in &b.steps {
        if !visit(&s.id, &by_id, &mut out, &mut state) {
            return None;
        }
    }
    Some(out)
}

/// DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. `None` when sound.
fn dag_error(b: &Body) -> Option<&'static str> {
    let mut ids = BTreeSet::new();
    for s in &b.steps {
        if !ids.insert(s.id.as_str()) {
            return Some("duplicate step id");
        }
    }
    for s in &b.steps {
        if s.deps.iter().any(|d| *d == s.id || !ids.contains(d.as_str())) {
            return Some("bad dependency");
        }
    }
    let Some(anc) = ancestors(b) else { return Some("cycle") };
    for e in &b.edges {
        if !ids.contains(e.from_step.as_str()) || !ids.contains(e.to_step.as_str()) || !anc.get(&e.to_step).is_some_and(|a| a.contains(&e.from_step)) {
            return Some("edge does not follow a dependency");
        }
    }
    None
}

// ---- commitment and receipts ------------------------------------------------------------------------------------------------

/// `hashCanonical({d: WF_REF, w: body})`; `None` where the reference throws.
pub fn workflow_digest(body: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": WF_REF, "w": body }))
}
pub fn receipt_ref(r: &Value) -> Option<String> {
    hash_canonical_strict(&json!({ "d": WR_REF, "r": r }))
}

struct Out {
    digest: String,
    num: Option<i64>,
    unit: Option<String>,
    labels: Vec<String>,
}
struct Rec {
    wf: String,
    step: String,
    seq: i64,
    prev: Option<String>,
    ok: bool,
    params_digest: String,
    outputs: BTreeMap<String, Out>,
    issued_at: i64,
    signer: String,
}
const RECEIPT_KEYS: [&str; 11] = ["v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer", "sig"];

fn parse_out(v: &Value) -> Option<Out> {
    let o = v.as_object().filter(|o| only_keys(o, &["digest", "num", "unit", "labels"]))?;
    if !(is_b32(o.get("digest")) && null_or(o.get("num"), is_uint) && null_or(o.get("unit"), is_unit)) {
        return None;
    }
    Some(Out { digest: opt_str(o.get("digest"))?, num: o.get("num").and_then(uint), unit: opt_str(o.get("unit")), labels: sorted_unique(o.get("labels"), is_label_str, MAX_LABELS)? })
}
fn parse_receipt(v: &Value) -> Option<Rec> {
    let r = v.as_object().filter(|r| only_keys(r, &RECEIPT_KEYS))?;
    if r.get("v").and_then(int) != Some(1) {
        return None;
    }
    let seq = r.get("seq").and_then(uint)?;
    let prev = opt_str(r.get("prev"));
    let outcome = r.get("outcome")?.as_str()?;
    if !(is_b32(r.get("wf")) && is_id(r.get("step")) && null_or(r.get("prev"), is_b32) && (seq == 0) == r.get("prev")?.is_null() && (outcome == "ok" || outcome == "failed")) {
        return None;
    }
    if !(is_b32(r.get("params_digest")) && is_uint(r.get("issued_at")) && is_b32(r.get("signer")) && r.get("sig")?.is_string()) {
        return None;
    }
    let o = r.get("outputs")?.as_object().filter(|o| o.len() <= MAX_FIELDS)?;
    let mut outputs = BTreeMap::new();
    for (k, x) in o {
        if !is_name_str(k) {
            return None;
        }
        outputs.insert(k.clone(), parse_out(x)?);
    }
    Some(Rec { wf: opt_str(r.get("wf"))?, step: opt_str(r.get("step"))?, seq, prev, ok: outcome == "ok", params_digest: opt_str(r.get("params_digest"))?, outputs, issued_at: r.get("issued_at").and_then(uint)?, signer: opt_str(r.get("signer"))? })
}
/// The receipt without its signature: the signed body.
fn rec_body(r: &Value) -> Value {
    let mut m = r.as_object().cloned().unwrap_or_default();
    m.remove("sig");
    Value::Object(m)
}

// ---- admission --------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Escalate,
}
impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Escalate => "escalate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfResult {
    pub decision: Decision,
    pub code: Option<&'static str>,
    pub step: Option<String>,
    /// index of the offending receipt (receipt-chain failures)
    pub at: Option<usize>,
    /// edge indexes whose source receipt does not exist yet (promise pipelining); each is re-checked by [`bind_promises`]
    pub pending: Vec<usize>,
}
impl WfResult {
    /// The shape of the shared vectors: `{decision, code, step, at, pending}`.
    pub fn to_json(&self) -> Value {
        json!({ "decision": self.decision.as_str(), "code": self.code, "step": self.step, "at": self.at, "pending": self.pending })
    }
}
fn res(decision: Decision, code: Option<&'static str>, step: Option<&str>, pending: Vec<usize>) -> WfResult {
    WfResult { decision, code, step: step.map(str::to_string), at: None, pending }
}
fn deny(code: &'static str, step: Option<&str>, at: Option<usize>) -> WfResult {
    WfResult { at, ..res(Decision::Deny, Some(code), step, vec![]) }
}

/// The caller's input, exactly as the reference takes it. Everything is a raw JSON value so hostile input denies instead of failing to type.
#[derive(Debug, Clone, Copy)]
pub struct AdmitInput<'a> {
    pub workflow: &'a Value,
    /// the principal key the verifier pinned: a key named inside the workflow is never trusted
    pub principal: &'a Value,
    /// the resource-server key the verifier pinned for step receipts
    pub rs_signer: &'a Value,
    pub receipts: &'a Value,
    pub now: &'a Value,
    pub request: &'a Value,
}

struct Request {
    step: String,
    verb: String,
    resource: String,
    params: Map<String, Value>,
    units: Map<String, Value>,
    goal_digest: Option<String>,
    plan_root: Option<String>,
}
fn parse_request(v: &Value) -> Option<Request> {
    let r = v.as_object().filter(|r| only_keys(r, &["step", "verb", "resource", "params", "units", "goal_digest", "plan_root"]))?;
    let units = r.get("units")?.as_object().filter(|u| u.iter().all(|(k, x)| is_name_str(k) && is_unit(Some(x))))?;
    if !(is_id(r.get("step")) && is_str(r.get("verb"), 128) && is_str(r.get("resource"), 512) && is_scalar_map(r.get("params")) && null_or(r.get("goal_digest"), is_b32) && null_or(r.get("plan_root"), is_b32)) {
        return None;
    }
    Some(Request {
        step: opt_str(r.get("step"))?,
        verb: opt_str(r.get("verb"))?,
        resource: opt_str(r.get("resource"))?,
        params: r.get("params")?.as_object()?.clone(),
        units: units.clone(),
        goal_digest: opt_str(r.get("goal_digest")),
        plan_root: opt_str(r.get("plan_root")),
    })
}

/// Is `root` the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes? (`plan_root_authorized`).
pub fn plan_root_authorized(workflow: &Value, principal: &str, now: i64, root: &str) -> bool {
    let Some(w) = workflow.as_object() else { return false };
    let Some(body) = w.get("body").and_then(parse_body) else { return false };
    dag_error(&body).is_none()
        && body.principal == principal
        && verify_body(WORKFLOW_DOMAIN, &w["body"], principal, w.get("sig").and_then(Value::as_str))
        && now >= body.issued_at
        && now < body.expires_at
        && body.plan_root.as_deref() == Some(root)
}

/// Check the receipt chain against the workflow. The parsed receipts, or `Err(Some(i))` at the offending index, or `Err(None)`
/// where the reference throws (a digest out of profile).
fn receipt_chain(w: &Body, wd: &str, rs_signer: &str, receipts: &[Value], now: i64) -> Result<Vec<Rec>, Option<usize>> {
    let by_id: BTreeMap<&str, &Step> = w.steps.iter().map(|s| (s.id.as_str(), s)).collect();
    let mut index: BTreeSet<String> = BTreeSet::new();
    let mut recs: Vec<Rec> = Vec::with_capacity(receipts.len());
    let mut prev_raw: Option<&Value> = None;
    for (i, raw) in receipts.iter().enumerate() {
        let Some(r) = parse_receipt(raw) else { return Err(Some(i)) };
        if r.signer != rs_signer || r.wf != wd || r.seq != i as i64 || r.issued_at > now {
            return Err(Some(i));
        }
        let Some(step) = by_id.get(r.step.as_str()) else { return Err(Some(i)) };
        if index.contains(&r.step) {
            return Err(Some(i));
        }
        let prev_ok = match prev_raw {
            None => r.prev.is_none(),
            Some(p) => r.prev.as_deref() == Some(receipt_ref(p).ok_or(None::<usize>)?.as_str()),
        };
        if !prev_ok || !verify_body(WF_RECEIPT_DOMAIN, &rec_body(raw), rs_signer, raw.get("sig").and_then(Value::as_str)) {
            return Err(Some(i));
        }
        // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
        for d in &step.deps {
            if index.contains(d) {
                continue;
            }
            let es: Vec<&Edge> = w.edges.iter().filter(|e| e.from_step == *d && e.to_step == r.step).collect();
            if es.is_empty() || es.iter().any(|e| e.promise.is_none()) {
                return Err(Some(i));
            }
        }
        index.insert(r.step.clone());
        recs.push(r);
        prev_raw = Some(raw);
    }
    Ok(recs)
}

/// `Err(())` is a throw in the reference (caught there as `bad_workflow`).
fn evaluate(inp: &AdmitInput, bind: bool) -> Result<WfResult, ()> {
    let bad_workflow = Ok(deny("bad_workflow", None, None));
    let Some(sw) = inp.workflow.as_object().filter(|o| only_keys(o, &["body", "sig"])) else { return bad_workflow };
    let (Some(w), Some(q), Some(receipts)) = (parse_body(&sw["body"]), parse_request(inp.request), inp.receipts.as_array()) else { return bad_workflow };
    let (Some(principal), Some(rs_signer), Some(now)) = (inp.principal.as_str().filter(|p| is_b32_str(p)), inp.rs_signer.as_str().filter(|p| is_b32_str(p)), uint(inp.now)) else { return bad_workflow };
    let qs = Some(q.step.as_str());
    if dag_error(&w).is_some() {
        return Ok(deny("bad_dag", qs, None));
    }
    if w.principal != principal || !verify_body(WORKFLOW_DOMAIN, &sw["body"], principal, sw["sig"].as_str()) {
        return Ok(deny("bad_signature", qs, None));
    }
    if now < w.issued_at {
        return Ok(deny("not_yet", qs, None));
    }
    if now >= w.expires_at {
        return Ok(deny("expired", qs, None));
    }
    if q.goal_digest != w.goal_digest {
        return Ok(deny("goal_mismatch", qs, None));
    }
    if q.plan_root != w.plan_root {
        return Ok(deny("plan_root_mismatch", qs, None));
    }
    let wd = workflow_digest(&sw["body"]).ok_or(())?;
    let recs = match receipt_chain(&w, &wd, rs_signer, receipts, now) {
        Ok(r) => r,
        Err(Some(at)) => return Ok(deny("bad_receipt", qs, Some(at))),
        Err(None) => return Err(()),
    };
    let rec: BTreeMap<&str, &Rec> = recs.iter().map(|r| (r.step.as_str(), r)).collect();
    let Some(step) = w.steps.iter().find(|s| s.id == q.step) else { return Ok(deny("unplanned_step", qs, None)) };
    if step.verb != q.verb || step.resource != q.resource {
        return Ok(deny("step_mismatch", qs, None));
    }
    let pd = hash_canonical_strict(&Value::Object(q.params.clone())).ok_or(())?;
    if step.params_digest.as_deref().is_some_and(|d| d != pd) {
        return Ok(deny("params_mismatch", qs, None));
    }
    let mine = rec.get(step.id.as_str());
    if bind {
        if !mine.is_some_and(|m| m.params_digest == pd) {
            return Ok(deny("params_mismatch", qs, None));
        }
    } else {
        if mine.is_some() {
            return Ok(deny("already_done", qs, None));
        }
        if recs.len() as i64 + 1 > w.max_steps {
            return Ok(deny("budget_exceeded", qs, None));
        }
        let cost_of = |id: &str, name: &str| w.steps.iter().find(|s| s.id == id).and_then(|s| s.cost.get(name)).copied().unwrap_or(0);
        for (name, cap) in &w.caps {
            let spent = recs.iter().fold(0i64, |a, r| a.saturating_add(cost_of(&r.step, name))).saturating_add(step.cost.get(name).copied().unwrap_or(0));
            if spent > *cap {
                return Ok(deny("budget_exceeded", qs, None));
            }
        }
    }
    // dependencies
    let mut pending: Vec<usize> = Vec::new();
    let mut unconstrained = false;
    for d in &step.deps {
        let Some(dr) = rec.get(d.as_str()) else {
            let es: Vec<&Edge> = w.edges.iter().filter(|e| e.from_step == *d && e.to_step == step.id).collect();
            if bind || es.is_empty() {
                return Ok(deny("deps_unmet", qs, None));
            }
            if es.iter().any(|e| e.promise.is_none()) {
                unconstrained = true;
            }
            continue;
        };
        if !dr.ok {
            return Ok(deny("dep_failed", qs, None));
        }
        if step.fresh_ms.is_some_and(|f| now - dr.issued_at > f) {
            return Ok(deny("stale_dep", qs, None));
        }
    }
    // edge constraints
    for (i, e) in w.edges.iter().enumerate() {
        if e.to_step != step.id {
            continue;
        }
        let Some(src) = rec.get(e.from_step.as_str()) else {
            pending.push(i);
            continue;
        };
        let (Some(out), Some(val)) = (src.outputs.get(&e.from_field), q.params.get(&e.to_param)) else { return Ok(deny("edge_missing", qs, Some(i))) };
        let qunit = q.units.get(&e.to_param).and_then(Value::as_str);
        if out.unit.as_deref() != qunit || out.unit != e.unit {
            return Ok(deny("edge_unit", qs, Some(i)));
        }
        if e.op == "eq" {
            if value_digest(val).ok_or(())? != out.digest {
                return Ok(deny("edge_digest", qs, Some(i)));
            }
        } else {
            let (Some(v), Some(n)) = (int(val), out.num) else { return Ok(deny("edge_value", qs, Some(i))) };
            let ok = match e.op.as_str() {
                "le" => v <= n,
                "ge" => v >= n,
                "lt" => v < n,
                _ => v > n,
            };
            if !ok {
                return Ok(deny("edge_relation", qs, Some(i)));
            }
        }
        if out.labels.iter().any(|l| e.deny_labels.contains(l)) {
            return Ok(deny("taint_flow", qs, Some(i)));
        }
    }
    if bind && !pending.is_empty() {
        return Ok(deny("deps_unmet", qs, None));
    }
    // taint across the DAG: every label any executed ancestor produced
    let anc = ancestors(&w).ok_or(())?;
    let mut inherited: BTreeSet<&str> = BTreeSet::new();
    for a in anc.get(&step.id).ok_or(())? {
        if let Some(r) = rec.get(a.as_str()) {
            for o in r.outputs.values() {
                inherited.extend(o.labels.iter().map(String::as_str));
            }
        }
    }
    if step.deny_labels.iter().any(|l| inherited.contains(l.as_str())) {
        return Ok(deny("taint_flow", qs, None));
    }
    if unconstrained {
        return Ok(res(Decision::Escalate, Some("pipeline_unconstrained"), qs, vec![]));
    }
    if step.escalate_labels.iter().any(|l| inherited.contains(l.as_str())) {
        return Ok(res(Decision::Escalate, Some("taint_escalate"), qs, vec![]));
    }
    Ok(res(Decision::Allow, None, qs, pending))
}

/// Admit ONE step of the committed workflow, or deny / escalate. Total: never panics.
pub fn admit_step(inp: &AdmitInput) -> WfResult {
    evaluate(inp, false).unwrap_or_else(|()| deny("bad_workflow", None, None))
}
/// Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge now that all of its
/// dependencies' receipts exist. A pipelined step whose promise turns out wrong is a violation (the caller revokes / compensates).
pub fn bind_promises(inp: &AdmitInput) -> WfResult {
    evaluate(inp, true).unwrap_or_else(|()| deny("bad_workflow", None, None))
}
