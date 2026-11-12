//! Policy classes (NIST NGAC idea): a decision is the meet of the answers of every class consulted, and the record names who said
//! no. Fail-strict: no class is a deny, a malformed list, a duplicate or an unknown class is a deny. Total: no function panics.
//! Port of packages/pca/src/policy-classes.ts; replays policy-classes-vectors.json.
use crate::decision::meet_all;
use crate::lease::{nat, s};
use crate::missing_context::js_keys;
use serde_json::Value;

pub const POLICY_CLASSES: [&str; 5] = ["constitution", "regulatory", "org", "blueprint", "user"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassVerdict {
    pub class: String,
    pub revision: i64,
    pub digest: String,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDecision {
    pub decision: &'static str,
    /// The classes consulted, in canonical order.
    pub classes: Vec<ClassVerdict>,
    pub denied_by: Vec<String>,
    pub escalated_by: Vec<String>,
    pub reason: Option<String>,
}

fn class_index(c: &str) -> Option<usize> {
    POLICY_CLASSES.iter().position(|x| *x == c)
}

/// `None` = a well-formed list: closed members, known classes, each at most once.
pub fn class_verdicts_error(list: &Value) -> Option<String> {
    let Some(arr) = list.as_array() else { return Some("policy classes must be an array".into()) };
    if arr.len() > POLICY_CLASSES.len() {
        return Some(format!("more than {} policy classes", POLICY_CLASSES.len()));
    }
    let mut seen: Vec<&str> = Vec::new();
    for (i, v) in arr.iter().enumerate() {
        let Some(o) = v.as_object() else { return Some(format!("policy_classes[{i}] must be an object")) };
        for k in js_keys(o) {
            if !matches!(k.as_str(), "class" | "revision" | "digest" | "decision") {
                return Some(format!("policy_classes[{i}] has unknown member '{k}'"));
            }
        }
        let Some(c) = o.get("class").and_then(Value::as_str).filter(|c| class_index(c).is_some()) else {
            return Some(format!("policy_classes[{i}].class is not a known class"));
        };
        if seen.contains(&c) {
            return Some(format!("policy class '{c}' appears twice"));
        }
        seen.push(c);
        if nat(o.get("revision")).is_none() {
            return Some(format!("policy_classes[{i}].revision must be a non-negative safe integer"));
        }
        if !s(o.get("digest"), 128) {
            return Some(format!("policy_classes[{i}].digest invalid"));
        }
        if !matches!(o.get("decision").and_then(Value::as_str), Some("allow" | "escalate" | "deny")) {
            return Some(format!("policy_classes[{i}].decision must be allow, escalate or deny"));
        }
    }
    None
}

fn deny(reason: String) -> ClassDecision {
    ClassDecision { decision: "deny", classes: vec![], denied_by: vec![], escalated_by: vec![], reason: Some(reason) }
}

pub fn decide_classes(list: &Value) -> ClassDecision {
    if list.as_array().is_some_and(Vec::is_empty) {
        return deny("no_policy_class".into());
    }
    if let Some(e) = class_verdicts_error(list) {
        return deny(format!("malformed policy classes: {e}"));
    }
    let text = |o: &Value, k: &str| o.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let mut classes: Vec<ClassVerdict> = list
        .as_array()
        .map(|a| a.iter().map(|o| ClassVerdict { class: text(o, "class"), revision: nat(o.get("revision")).unwrap_or(0), digest: text(o, "digest"), decision: text(o, "decision") }).collect())
        .unwrap_or_default();
    classes.sort_by_key(|c| class_index(&c.class)); // stable
    let ds: Vec<&str> = classes.iter().map(|c| c.decision.as_str()).collect();
    let by = |d: &str| classes.iter().filter(|c| c.decision == d).map(|c| c.class.clone()).collect::<Vec<_>>();
    let decision = match meet_all(&ds) {
        "allow" => "allow",
        "escalate" => "escalate",
        _ => "deny",
    };
    ClassDecision { decision, denied_by: by("deny"), escalated_by: by("escalate"), classes: classes.clone(), reason: None }
}
