//! L4 information-flow taint and the `enforce.taint` gate (port of `taint.ts`). The agent's own label is never read: every declared
//! provenance ref is re-classified from facts the SERVER holds (a trusted-input registry it populated, or its own committed resource
//! graph); a ref the server cannot vouch for is `agent` (the worst case). Pure and deterministic; absent or malformed provenance and any
//! internal error (a panicking registry included) fail CLOSED to taint 1.
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::intent_v2::js_number_string;

/// The label lattice, least trusted last: `trusted < first_party < tool < web < agent`.
pub const TAINT_LEVELS: [&str; 5] = ["trusted", "first_party", "tool", "web", "agent"];
const MAX_RANK: usize = 4;

/// A taint label: a level name and, for `tool` / `agent`, an explanatory id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintLabel {
    pub kind: String,
    pub id: Option<String>,
}

impl TaintLabel {
    pub fn new(kind: &str) -> TaintLabel {
        TaintLabel { kind: kind.to_string(), id: None }
    }
    fn with_id(kind: &str, id: &str) -> TaintLabel {
        TaintLabel { kind: kind.to_string(), id: Some(id.to_string()) }
    }
}

/// True only for the five real level names.
pub fn is_taint_level(kind: &str) -> bool {
    TAINT_LEVELS.contains(&kind)
}

/// Rank of a label; an unknown kind is the WORST rank (fail closed).
pub fn label_rank(l: &TaintLabel) -> usize {
    TAINT_LEVELS.iter().position(|k| *k == l.kind).unwrap_or(MAX_RANK)
}

/// Normalized taint of a label: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1.
pub fn taint_value(l: &TaintLabel) -> f64 {
    label_rank(l) as f64 / MAX_RANK as f64
}

/// Least upper bound: the higher-ranked label; equal ranks keep the id only when both agree, else the generic representative.
pub fn join_label(a: &TaintLabel, b: &TaintLabel) -> TaintLabel {
    let (ra, rb) = (label_rank(a), label_rank(b));
    if ra > rb {
        return a.clone();
    }
    if rb > ra {
        return b.clone();
    }
    if a.id == b.id {
        return a.clone();
    }
    TaintLabel::new(&a.kind)
}

/// Join over a list of labels; the EMPTY lineage joins to the worst case ("no verifiable trusted input" is not "trusted").
pub fn join_labels(labels: &[TaintLabel]) -> TaintLabel {
    match labels.split_first() {
        None => TaintLabel::new("agent"),
        Some((first, rest)) => rest.iter().fold(first.clone(), |acc, l| join_label(&acc, l)),
    }
}

/// The inputs the SERVER independently vouches for, keyed by content digest.
pub trait TrustedInputRegistry: Send + Sync {
    fn lookup(&self, digest: &str) -> Option<TaintLabel>;
}

/// The server's in-process registry. Only the server populates it; nothing an agent sends reaches it.
#[derive(Debug, Default)]
pub struct InMemoryTrustedInputRegistry {
    m: Mutex<HashMap<String, TaintLabel>>,
}

impl InMemoryTrustedInputRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record that `digest` is an input the server verified at `label` (an empty digest or an unknown level is ignored).
    pub fn record(&self, digest: &str, label: TaintLabel) -> &Self {
        if !digest.is_empty() && is_taint_level(&label.kind) {
            if let Ok(mut m) = self.m.lock() {
                m.insert(digest.to_string(), label);
            }
        }
        self
    }
    pub fn record_trusted(&self, digest: &str) -> &Self {
        self.record(digest, TaintLabel::new("trusted"))
    }
    pub fn record_first_party(&self, digest: &str) -> &Self {
        self.record(digest, TaintLabel::new("first_party"))
    }
    pub fn record_tool(&self, digest: &str, id: &str) -> &Self {
        self.record(digest, TaintLabel::with_id("tool", id))
    }
    pub fn record_web(&self, digest: &str) -> &Self {
        self.record(digest, TaintLabel::new("web"))
    }
    pub fn size(&self) -> usize {
        self.m.lock().map_or(0, |m| m.len())
    }
}

impl TrustedInputRegistry for InMemoryTrustedInputRegistry {
    fn lookup(&self, digest: &str) -> Option<TaintLabel> {
        self.m.lock().ok()?.get(digest).cloned()
    }
}

/// The server's committed resource graph, read only: does it have a node `id`?
pub trait ResourceGraphNodes: Send + Sync {
    fn node(&self, id: &str) -> bool;
}

/// Independently classify ONE declared ref (never reading the agent's own label): the registry's label, else first_party for a node of
/// the resource graph, else agent. A non-string or empty ref is malformed (agent).
pub fn classify_ref(r: &Value, registry: &dyn TrustedInputRegistry, graph: Option<&dyn ResourceGraphNodes>) -> TaintLabel {
    let s = match r.as_str() {
        Some(s) if !s.is_empty() => s,
        _ => return TaintLabel::new("agent"),
    };
    if let Some(v) = registry.lookup(s) {
        if is_taint_level(&v.kind) {
            return v;
        }
    }
    if graph.is_some_and(|g| catch_unwind(AssertUnwindSafe(|| g.node(s))).unwrap_or(false)) {
        return TaintLabel::new("first_party");
    }
    // 128 UTF-16 code units, as `ref.length <= 128`
    if s.encode_utf16().count() <= 128 {
        TaintLabel::with_id("agent", s)
    } else {
        TaintLabel::new("agent")
    }
}

/// The taint of a PCActn's provenance: `Ok((taint, label))` or `Err(reason)` when the lineage is not valid (then the taint is 1).
pub fn compute_taint(provenance: &Value, registry: &dyn TrustedInputRegistry, graph: Option<&dyn ResourceGraphNodes>) -> Result<(f64, TaintLabel), String> {
    let obj = provenance.as_object().ok_or_else(|| "taint: provenance is absent or malformed".to_string())?;
    let mut refs: Vec<&Value> = Vec::new();
    if let Some(raw) = obj.get("trusted_refs") {
        let list = raw.as_array().ok_or_else(|| "taint: trusted_refs must be an array".to_string())?;
        if !list.iter().all(|r| r.as_str().is_some_and(|s| !s.is_empty())) {
            return Err("taint: trusted_refs must be non-empty strings".into());
        }
        refs = list.iter().collect();
    }
    catch_unwind(AssertUnwindSafe(|| {
        let labels: Vec<TaintLabel> = refs.iter().map(|r| classify_ref(r, registry, graph)).collect();
        let label = join_labels(&labels);
        (taint_value(&label), label)
    }))
    .map_err(|e| format!("taint: evaluation error (fail closed): {}", panic_message(e.as_ref())))
}

/// The message of a panic payload (the reference reads `Error.message`, else `unknown`).
pub fn panic_message(e: &(dyn std::any::Any + Send)) -> String {
    e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_else(|| "unknown".to_string())
}

/// The `enforce.taint` gate: the registry, the optional resource graph and the largest taint the policy accepts.
#[derive(Clone)]
pub struct TaintGate {
    pub registry: Arc<dyn TrustedInputRegistry>,
    pub resource_graph: Option<Arc<dyn ResourceGraphNodes>>,
    pub max_taint: f64,
}

/// `Ok` or the refusal reason. A negative or non-finite `max_taint` is a misconfiguration and never passes.
pub fn taint_gate_check(provenance: &Value, g: &TaintGate) -> Result<(), String> {
    let (taint, label) = compute_taint(provenance, g.registry.as_ref(), g.resource_graph.as_deref())?;
    if !(g.max_taint.is_finite() && g.max_taint >= 0.0) {
        return Err("taint gate misconfigured: maxTaint must be a non-negative number (fail closed)".into());
    }
    let allowed = (0..=MAX_RANK).filter(|r| *r as f64 / MAX_RANK as f64 <= g.max_taint).max();
    if allowed.is_some_and(|a| label_rank(&label) <= a) {
        Ok(())
    } else {
        Err(format!("information-flow taint {} exceeds policy max {}", js_number_string(taint), js_number_string(g.max_taint)))
    }
}
