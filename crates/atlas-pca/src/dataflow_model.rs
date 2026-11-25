//! The capability-tagged, positive data-flow model (CaMeL style; the core `dataflow` module of the reference): `tag` and the
//! boundary constructors, the capability algebra, `classify_flow` / `can_flow`, the action gate `check_action`, `dual_context`,
//! the sink presets and `level_of`. Pure and deterministic.
//!
//! Rust shape: a [`Tagged`] value can only be made by this module (its fields are private, there is no public constructor
//! other than `tag`, `from_*` and `derive`), so "an untagged value" is an `Option<&Tagged>` that is `None`. Capability sets are
//! insertion-ordered, de-duplicated vectors (a JS `Set`); sources print sorted by UTF-16 code unit like `Array.sort()`.
//! Stricter than the reference: capability sources / readers must be strings; a sink whose `allowedSources` / `deniedSources`
//! is present but not a list is an invalid sink (the reference would throw on it).
use crate::intent_v2::js_number_string;
use serde_json::{json, Map, Value};

pub const TRUSTED_QUERY: &str = "trusted-query";

/// Provenance tag of the output of a named tool (always untrusted).
pub fn tool_provenance(name: &str) -> String {
    format!("tool:{name}")
}

fn u16cmp(a: &String, b: &String) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn dedup(xs: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in xs {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

fn sorted(xs: &[String]) -> Vec<String> {
    let mut v = xs.to_vec();
    v.sort_by(u16cmp);
    v
}

/// What a value carries: `sources` (lineage, insertion order), `is_trusted` (every source trusted) and the optional
/// `readers` allow-list of sink ids.
#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    pub sources: Vec<String>,
    pub is_trusted: bool,
    pub readers: Option<Vec<String>>,
}

impl Capability {
    pub fn new(sources: impl IntoIterator<Item = String>, is_trusted: bool, readers: Option<Vec<String>>) -> Capability {
        Capability { sources: dedup(sources), is_trusted, readers: readers.map(dedup) }
    }

    /// `{sources:[..], isTrusted, readers?:[..]}`. Err when it is not an object, `sources` is not a list of strings,
    /// `isTrusted` is not a boolean, or `readers` is present and not a list of strings (the checks `tag` makes).
    pub fn from_json(v: &Value) -> Result<Capability, String> {
        const MSG: &str = "tag: a capability needs a set of sources and a boolean isTrusted";
        let o = v.as_object().ok_or(MSG)?;
        let strs = |x: &Value| -> Option<Vec<String>> { x.as_array()?.iter().map(|s| s.as_str().map(str::to_string)).collect() };
        let sources = o.get("sources").and_then(strs).ok_or(MSG)?;
        let is_trusted = o.get("isTrusted").and_then(Value::as_bool).ok_or(MSG)?;
        let readers = match o.get("readers") {
            None => None,
            Some(r) => Some(strs(r).ok_or("tag: readers must be a Set when given")?),
        };
        Ok(Capability::new(sources, is_trusted, readers))
    }

    /// `{sources, isTrusted, readers?}` with the sets in insertion order.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("sources".into(), json!(self.sources));
        m.insert("isTrusted".into(), json!(self.is_trusted));
        if let Some(r) = &self.readers {
            m.insert("readers".into(), json!(r));
        }
        Value::Object(m)
    }
}

/// A value carrying its capability. Only this module can make one.
#[derive(Debug, Clone, PartialEq)]
pub struct Tagged {
    value: Value,
    cap: Capability,
}

impl Tagged {
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn cap(&self) -> &Capability {
        &self.cap
    }
    /// `{value, cap}`.
    pub fn to_json(&self) -> Value {
        json!({"value": self.value, "cap": self.cap.to_json()})
    }
}

/// Tag a value with an explicit capability (the escape hatch; prefer the boundary constructors). A trusted capability needs
/// a source and no `tool:` source.
pub fn tag(value: Value, cap: &Capability) -> Result<Tagged, String> {
    if cap.is_trusted {
        if cap.sources.is_empty() {
            return Err("tag: a trusted capability needs at least one source".into());
        }
        if cap.sources.iter().any(|s| s.starts_with("tool:")) {
            return Err("tag: tool output can never be trusted".into());
        }
    }
    Ok(Tagged { value, cap: Capability::new(cap.sources.clone(), cap.is_trusted, cap.readers.clone()) })
}

fn mint(value: Value, cap: Capability) -> Tagged {
    Tagged { value, cap }
}

/// The genuine user query: trusted, source `trusted-query`.
pub fn from_trusted_query(value: Value, readers: Option<&[String]>) -> Tagged {
    mint(value, Capability::new([TRUSTED_QUERY.to_string()], true, readers.map(<[String]>::to_vec)))
}

/// The output of a named tool: always untrusted.
pub fn from_tool_output(name: &str, value: Value, readers: Option<&[String]>) -> Tagged {
    mint(value, Capability::new([tool_provenance(name)], false, readers.map(<[String]>::to_vec)))
}

/// A value from a named source; untrusted unless the caller vouches (`is_trusted`). A trusted `tool:` source is refused.
pub fn from_source(source: &str, value: Value, is_trusted: bool, readers: Option<&[String]>) -> Result<Tagged, String> {
    tag(value, &Capability::new([source.to_string()], is_trusted, readers.map(<[String]>::to_vec)))
}

/// Union of the sources of several capabilities (first-seen order).
pub fn union_sources(caps: &[Capability]) -> Vec<String> {
    dedup(caps.iter().flat_map(|c| c.sources.iter().cloned()))
}

/// sources = union, `is_trusted` = AND over a non-empty list, readers = intersection of the inputs that restrict readers.
pub fn combine_caps(caps: &[Capability]) -> Capability {
    let mut readers: Option<Vec<String>> = None;
    for c in caps {
        let Some(r) = &c.readers else { continue };
        readers = Some(match readers {
            None => r.clone(),
            Some(cur) => cur.into_iter().filter(|x| r.contains(x)).collect(),
        });
    }
    Capability::new(union_sources(caps), !caps.is_empty() && caps.iter().all(|c| c.is_trusted), readers)
}

/// A new tagged value whose capability is `combine_caps` over the inputs: trust can only be lost. The combiner's error
/// propagates.
pub fn derive(inputs: &[Tagged], combine: impl FnOnce(&[Value]) -> Result<Value, String>) -> Result<Tagged, String> {
    let values: Vec<Value> = inputs.iter().map(|t| t.value.clone()).collect();
    let value = combine(&values)?;
    let caps: Vec<Capability> = inputs.iter().map(|t| t.cap.clone()).collect();
    Ok(mint(value, combine_caps(&caps)))
}

// ---- sinks + the policy interpreter ------------------------------------------------------------------------------------

/// What a sink accepts (`external`, `requireTrusted`, `allowedSources`, `deniedSources`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlowPolicy {
    pub external: bool,
    pub require_trusted: bool,
    pub allowed_sources: Option<Vec<String>>,
    pub denied_sources: Option<Vec<String>>,
}

/// A place a value leaves the trusted interior. `accepts` is `None` for a sink whose policy is not an object (invalid, so a
/// flow to it is refused); an empty `id` is invalid too.
#[derive(Debug, Clone, PartialEq)]
pub struct Sink {
    pub id: String,
    pub accepts: Option<FlowPolicy>,
}

impl Sink {
    pub fn new(id: &str, accepts: FlowPolicy) -> Sink {
        Sink { id: id.to_string(), accepts: Some(accepts) }
    }

    /// `{id, accepts:{external?, requireTrusted?, allowedSources?:[..], deniedSources?:[..]}}`. Never fails: whatever is not
    /// a usable sink becomes an invalid one (empty id and/or `accepts: None`), which `classify_flow` refuses.
    pub fn from_json(v: &Value) -> Sink {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let list = |m: &Map<String, Value>, k: &str| -> Result<Option<Vec<String>>, ()> {
            match m.get(k) {
                None => Ok(None),
                Some(Value::Array(a)) => Ok(Some(a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())),
                Some(_) => Err(()),
            }
        };
        let accepts = match v.get("accepts") {
            Some(Value::Object(m)) => match (list(m, "allowedSources"), list(m, "deniedSources")) {
                (Ok(allowed_sources), Ok(denied_sources)) => Some(FlowPolicy {
                    external: m.get("external") == Some(&Value::Bool(true)),
                    require_trusted: m.get("requireTrusted") == Some(&Value::Bool(true)),
                    allowed_sources,
                    denied_sources,
                }),
                _ => None,
            },
            Some(Value::Array(_)) => Some(FlowPolicy::default()),
            _ => None,
        };
        Sink { id, accepts }
    }

    pub fn to_json(&self) -> Value {
        let mut a = Map::new();
        if let Some(p) = &self.accepts {
            if p.external {
                a.insert("external".into(), json!(true));
            }
            if p.require_trusted {
                a.insert("requireTrusted".into(), json!(true));
            }
            if let Some(x) = &p.allowed_sources {
                a.insert("allowedSources".into(), json!(x));
            }
            if let Some(x) = &p.denied_sources {
                a.insert("deniedSources".into(), json!(x));
            }
        }
        json!({"id": self.id, "accepts": a})
    }
}

/// The shared allow / step_up / deny vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    StepUp,
    Deny,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::StepUp => "step_up",
            Outcome::Deny => "deny",
        }
    }
    fn severity(self) -> u8 {
        self as u8
    }
}

/// The decision for one value to sink flow, with the responsible provenance path.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowDecision {
    pub outcome: Outcome,
    pub reason: Option<String>,
    pub path: Option<Vec<String>>,
}

impl FlowDecision {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("outcome".into(), json!(self.outcome.as_str()));
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        if let Some(p) = &self.path {
            m.insert("path".into(), json!(p));
        }
        Value::Object(m)
    }
}

fn decision(outcome: Outcome, reason: String, path: Vec<String>) -> FlowDecision {
    FlowDecision { outcome, reason: Some(reason), path: Some(path) }
}

/// Classify one flow (`None` = a value this module did not tag: no provenance, no flow). Order: the value's readers, the
/// sink's denied sources, its allow-list, the external-sink rule, the sensitive-sink rule.
pub fn classify_flow(value: Option<&Tagged>, sink: &Sink) -> FlowDecision {
    let Some(value) = value else {
        return decision(Outcome::Deny, "value carries no provenance tag made by this module (fail closed)".into(), vec![]);
    };
    let cap = &value.cap;
    let srcs = sorted(&cap.sources);
    let p = match (&sink.accepts, sink.id.is_empty()) {
        (Some(p), false) => p,
        _ => return decision(Outcome::Deny, "the sink is not a valid sink (fail closed)".into(), srcs),
    };
    let id = &sink.id;
    if let Some(readers) = &cap.readers {
        if !readers.contains(id) {
            let list = sorted(readers).join(", ");
            let list = if list.is_empty() { "\u{2205}".to_string() } else { list };
            return decision(Outcome::Deny, format!("value's readers capability [{list}] does not include sink '{id}'"), srcs);
        }
    }
    if let Some(denied) = &p.denied_sources {
        let bad: Vec<String> = srcs.iter().filter(|s| denied.contains(s)).cloned().collect();
        if !bad.is_empty() {
            return decision(Outcome::Deny, format!("provenance [{}] is forbidden at sink '{id}'", bad.join(", ")), bad);
        }
    }
    if let Some(allowed) = &p.allowed_sources {
        let bad: Vec<String> = srcs.iter().filter(|s| !allowed.contains(s)).cloned().collect();
        if !bad.is_empty() {
            return decision(Outcome::Deny, format!("provenance [{}] is not in the allow-list of sink '{id}'", bad.join(", ")), bad);
        }
    }
    if p.external && !cap.is_trusted {
        let reason = format!(
            "untrusted value (provenance [{}]) may not flow to external-send sink '{id}' \u{2014} exfiltration / prompt-injection path",
            srcs.join(", ")
        );
        return decision(Outcome::Deny, reason, srcs);
    }
    if p.require_trusted && !cap.is_trusted {
        let reason = format!("sink '{id}' requires trusted provenance; value provenance [{}] is untrusted \u{2014} needs human review", srcs.join(", "));
        return decision(Outcome::StepUp, reason, srcs);
    }
    FlowDecision { outcome: Outcome::Allow, reason: None, path: None }
}

/// `{ok, reason?}`: `ok` only for a clean allow (a step_up is not ok without a human).
pub fn can_flow(value: Option<&Tagged>, sink: &Sink) -> (bool, Option<String>) {
    let d = classify_flow(value, sink);
    (d.outcome == Outcome::Allow, d.reason)
}

/// One argument of an action as the gate sees it.
#[derive(Debug, Clone, Copy)]
pub enum Arg<'a> {
    Tagged(&'a Tagged),
    /// A value this module did not tag: refused.
    Untagged,
    /// An explicit `undefined`: skipped (as the reference does).
    Undefined,
    /// A hole in the list, an argument nobody tagged: refused.
    Hole,
}

/// The gate's decision for an action.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionDecision {
    pub outcome: Outcome,
    pub sink: String,
    pub reason: Option<String>,
    pub arg: Option<usize>,
    pub path: Option<Vec<String>>,
}

impl ActionDecision {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("outcome".into(), json!(self.outcome.as_str()));
        m.insert("sink".into(), json!(self.sink));
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        if let Some(a) = self.arg {
            m.insert("arg".into(), json!(a));
        }
        if let Some(p) = &self.path {
            m.insert("path".into(), json!(p));
        }
        Value::Object(m)
    }
}

fn refuse(sink: &str, reason: String) -> ActionDecision {
    ActionDecision { outcome: Outcome::Deny, sink: sink.to_string(), reason: Some(reason), arg: None, path: None }
}

/// Gate an action by data flow: every argument is checked against the sink the governor resolves for the action; the worst
/// outcome wins (deny, then step_up, then allow). A governor that errs, or returns a sink with an empty id, is a refusal;
/// so is an argument count other than `expected_args` when given.
pub fn check_action(action: &Value, args: &[Arg], governor: &dyn Fn(&Value) -> Result<Sink, String>, expected_args: Option<f64>) -> ActionDecision {
    let sink = match governor(action) {
        Err(_) => return refuse("(unresolved)", "the sink for this action could not be resolved (fail closed)".into()),
        Ok(s) if s.id.is_empty() => return refuse("(unresolved)", "the sink for this action is not a valid sink (fail closed)".into()),
        Ok(s) => s,
    };
    if let Some(e) = expected_args {
        if args.len() as f64 != e {
            return refuse(&sink.id, format!("expected {} tagged argument(s), got {} (fail closed)", js_number_string(e), args.len()));
        }
    }
    let mut worst = ActionDecision { outcome: Outcome::Allow, sink: sink.id.clone(), reason: None, arg: None, path: None };
    for (i, a) in args.iter().enumerate() {
        let d = match a {
            Arg::Undefined => continue,
            Arg::Hole => {
                worst = ActionDecision { arg: Some(i), ..refuse(&sink.id, "an argument was not tagged (fail closed)".into()) };
                break;
            }
            Arg::Untagged => classify_flow(None, &sink),
            Arg::Tagged(t) => classify_flow(Some(t), &sink),
        };
        if d.outcome.severity() > worst.outcome.severity() {
            worst = ActionDecision { outcome: d.outcome, sink: sink.id.clone(), reason: d.reason, arg: Some(i), path: d.path };
        }
    }
    worst
}

/// The dual-LLM separation: the privileged `plan` sees only the TRUSTED query value; the quarantined handler returns a
/// tagged result (`None` = it returned something this module did not tag: refused). `query` is `None` for an untagged query.
pub fn dual_context(
    query: Option<&Tagged>,
    plan: impl FnOnce(&Value) -> Result<Value, String>,
    quarantine: impl FnOnce(&Value) -> Result<Option<Tagged>, String>,
) -> Result<(Value, Tagged), String> {
    let q = query.ok_or("dualContext: the query must be a tagged value made by this module")?;
    if !q.cap.is_trusted {
        return Err(format!("dualContext: the privileged planner may only run on a TRUSTED query; got provenance [{}]", sorted(&q.cap.sources).join(", ")));
    }
    let p = plan(&q.value)?;
    let result = quarantine(&p)?.ok_or("dualContext: the quarantined handler must return a tagged value made by this module")?;
    Ok((p, result))
}

/// An external-send sink (exfiltrating: untrusted values hard-deny).
pub fn external_send_sink(id: &str) -> Sink {
    Sink::new(id, FlowPolicy { external: true, ..Default::default() })
}

/// A sensitive internal sink (untrusted values step up for review).
pub fn sensitive_sink(id: &str) -> Sink {
    Sink::new(id, FlowPolicy { require_trusted: true, ..Default::default() })
}

/// A tagged value's label in the verifier's lattice: `trusted`, `tool` (every source a `tool:` output) or `agent`; an
/// untagged value is `agent`.
pub fn level_of(value: Option<&Tagged>) -> &'static str {
    let Some(v) = value else { return "agent" };
    if v.cap.is_trusted {
        "trusted"
    } else if !v.cap.sources.is_empty() && v.cap.sources.iter().all(|s| s.starts_with("tool:")) {
        "tool"
    } else {
        "agent"
    }
}
