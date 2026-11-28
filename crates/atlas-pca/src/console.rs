//! The principal's agent console, data layer (port of `console.ts`): projects a stream of activity events into a per-agent view
//! with a threat read (the behavioral immune system's), and models the local kill switch.
//!
//! Pure and offline: a projection over the records it is fed. The freeze set is the fast layer a client or gateway consults
//! before dispatching; authoritative revocation is the revocation epoch of the transparency ledger.
//!
//! JSON-valued (`&Value` in, the reference's member names out). A reference throw is an `Err`.
use serde_json::{json, Map, Value};

use crate::immune::{assess, observe, ImmuneState};
use crate::intent_v2::js_value_string;
use crate::prohibitions::num_value;

/// A finite JSON number.
fn finite(v: Option<&Value>) -> Option<f64> {
    v.filter(|n| n.is_number()).and_then(Value::as_f64).filter(|f| f.is_finite())
}

/// The activity event `{at, agent, verb, resource, outcome, r, taint, digest}` of a PCActn and the verifier's outcome (`auto`,
/// `step_up`, `deny` or `executed`). The agent is the holder of the leaf capability (`unknown` when the chain names none), the
/// time is `at` or else the action's `iat`, and the digest is the strict canonical hash of the action. `Err` for an action
/// without a capability chain or an `action`, and for one outside the strict canonical profile.
pub fn event_from_pcactn(p: &Value, outcome: &str, at: Option<f64>) -> Result<Value, String> {
    let chain = p.get("cap_chain").and_then(Value::as_array).ok_or("eventFromPCActn: the action carries no capability chain")?;
    let action = p.get("action").filter(|a| !a.is_null()).ok_or("eventFromPCActn: the action carries no action")?;
    let digest = crate::hash_canonical_strict(p).ok_or("eventFromPCActn: the action is outside the canonical profile")?;
    let mut e = Map::new();
    match at {
        Some(at) => e.insert("at".into(), num_value(at)),
        None => p.get("iat").and_then(|iat| e.insert("at".into(), iat.clone())),
    };
    let holder = chain.last().and_then(|leaf| leaf.get("holder")).filter(|h| !h.is_null());
    e.insert("agent".into(), holder.cloned().unwrap_or_else(|| json!("unknown")));
    for k in ["verb", "resource"] {
        if let Some(v) = action.get(k) {
            e.insert(k.into(), v.clone());
        }
    }
    e.insert("outcome".into(), json!(outcome));
    for (k, from, member) in [("r", "risk_claim", "r"), ("taint", "provenance", "taint_level")] {
        if let Some(v) = p.get(from).and_then(|o| o.get(member)) {
            e.insert(k.into(), v.clone());
        }
    }
    e.insert("digest".into(), json!(digest));
    Ok(Value::Object(e))
}

/// Projects activity events into the console view `{agents: [{agent, actions, autos, stepUps, denies, executed, totalRisk,
/// firstSeen, lastSeen, threat}], totals, window: {from, to}, dropped}`. Agents are ordered by threat score, then by the most
/// recent activity. An event that is not an object with a finite `at` and a non-empty `agent` cannot be placed or attributed:
/// it is counted in `dropped`, never guessed. A risk `r` that is not a number counts as 0.
pub fn build_console(events: &[Value]) -> Value {
    let usable = |e: &&Value| finite(e.get("at")).is_some() && e.get("agent").and_then(Value::as_str).is_some_and(|a| !a.is_empty());
    let kept: Vec<&Value> = events.iter().filter(usable).collect();
    fn at(e: &Value) -> f64 {
        finite(e.get("at")).unwrap_or(0.0)
    }
    let mut by_agent: Vec<(&str, Vec<&Value>)> = Vec::new();
    for &e in &kept {
        let agent = e["agent"].as_str().unwrap_or("");
        match by_agent.iter_mut().find(|(a, _)| *a == agent) {
            Some((_, list)) => list.push(e),
            None => by_agent.push((agent, vec![e])),
        }
    }
    // (threat score, last seen, summary)
    let mut agents: Vec<(f64, f64, Value)> = Vec::new();
    let mut totals = [0u64; 5];
    for (agent, mut list) in by_agent {
        list.sort_by(|a, b| at(a).partial_cmp(&at(b)).unwrap_or(std::cmp::Ordering::Equal));
        let list = list;
        let mut immune = ImmuneState::initial();
        let (mut counts, mut total_risk) = ([0u64; 4], 0.0f64);
        for e in &list {
            let r = e.get("r").filter(|r| r.is_number()).and_then(Value::as_f64).unwrap_or(0.0);
            total_risk += r;
            let outcome = e.get("outcome").and_then(Value::as_str).unwrap_or("");
            if let Some(i) = ["auto", "step_up", "deny", "executed"].iter().position(|o| *o == outcome) {
                counts[i] += 1;
            }
            immune = observe(&immune, r, at(e), outcome == "step_up", outcome == "deny");
        }
        let threat = assess(&immune.to_value());
        let (first, last) = (list.first().map_or(0.0, |e| at(e)), list.last().map_or(0.0, |e| at(e)));
        totals[0] += list.len() as u64;
        totals.iter_mut().skip(1).zip(counts).for_each(|(t, c)| *t += c);
        let summary = json!({"agent": agent, "actions": list.len(), "autos": counts[0], "stepUps": counts[1], "denies": counts[2], "executed": counts[3],
            "totalRisk": num_value(total_risk), "firstSeen": num_value(first), "lastSeen": num_value(last), "threat": threat.to_value()});
        agents.push((threat.score, last, summary));
    }
    agents.sort_by(|a, b| b.0.partial_cmp(&a.0).filter(|o| o.is_ne()).or_else(|| b.1.partial_cmp(&a.1)).unwrap_or(std::cmp::Ordering::Equal));
    let times = kept.iter().map(|e| at(e));
    let (from, to) = (times.clone().fold(f64::INFINITY, f64::min), times.fold(f64::NEG_INFINITY, f64::max));
    json!({
        "agents": agents.into_iter().map(|a| a.2).collect::<Vec<_>>(),
        "totals": {"actions": totals[0], "autos": totals[1], "stepUps": totals[2], "denies": totals[3], "executed": totals[4]},
        "window": {"from": if kept.is_empty() { json!(0) } else { num_value(from) }, "to": if kept.is_empty() { json!(0) } else { num_value(to) }},
        "dropped": events.len() - kept.len(),
    })
}

/// The agents of a console view whose threat read is not calm.
pub fn anomalies(view: &Value) -> Vec<Value> {
    let agents = view.get("agents").and_then(Value::as_array).into_iter().flatten();
    agents.filter(|a| a["threat"]["level"] != "calm").cloned().collect()
}

// ---- freeze (the kill switch) -------------------------------------------------------------------------------------------------

/// The empty freeze set `{frozen: []}`.
pub fn empty_freeze() -> Value {
    json!({ "frozen": [] })
}

/// The reference's name for [`empty_freeze`].
pub static EMPTY_FREEZE: std::sync::LazyLock<Value> = std::sync::LazyLock::new(empty_freeze);

/// The default ECMAScript sort order of the values' string forms (UTF-16 code units).
fn js_sort(list: &mut [Value]) {
    list.sort_by_cached_key(|v| js_value_string(v).encode_utf16().collect::<Vec<u16>>());
}

/// Freezes `agent` (a non-empty string): the same set when it is already frozen, else a new set with the agent added and the
/// list sorted. `Err` for an agent that is not a non-empty string, or a set without a `frozen` list.
pub fn freeze_agent(set: &Value, agent: &Value) -> Result<Value, String> {
    let name = agent.as_str().filter(|a| !a.is_empty()).ok_or("freezeAgent: agent must be a non-empty string")?;
    let mut list = match set.get("frozen") {
        Some(Value::Array(a)) if a.contains(agent) => return Ok(set.clone()),
        Some(Value::Array(a)) => a.clone(),
        // the reference reads a string as the list of its characters
        Some(Value::String(s)) if s.contains(name) => return Ok(set.clone()),
        Some(Value::String(s)) => s.chars().map(|c| json!(c.to_string())).collect(),
        _ => return Err("freezeAgent: the set has no frozen list".into()),
    };
    list.push(agent.clone());
    js_sort(&mut list);
    Ok(json!({ "frozen": list }))
}

/// A new set without `agent`. `Err` for a set whose `frozen` is not a list.
pub fn unfreeze_agent(set: &Value, agent: &Value) -> Result<Value, String> {
    let list = set.get("frozen").and_then(Value::as_array).ok_or("unfreezeAgent: the set has no frozen list")?;
    Ok(json!({ "frozen": list.iter().filter(|a| *a != agent).collect::<Vec<_>>() }))
}

/// Whether `agent` is frozen. Fails closed: an agent that is not a non-empty string, or a malformed set, is frozen.
pub fn is_frozen(set: &Value, agent: &Value) -> bool {
    match (set.get("frozen").and_then(Value::as_array), agent.as_str()) {
        (Some(list), Some(name)) if !name.is_empty() => list.contains(agent),
        _ => true,
    }
}
