//! Policy plumbing for the intent layer: an outcome as the analyzer's concrete action, and the real evaluator as an admission oracle.
use super::omega::VerbSpace;
use super::*;
use serde_json::{Map, Value};

pub const ANY_RESOURCE: &str = "resource:any";

/// `{predicates, caveats}`: a non-array member counts as empty.
pub fn normalize_policy(p: &Value) -> Value {
    let arr = |k: &str| match get(p, k) {
        Some(Value::Array(a)) => Value::Array(a.clone()),
        _ => Value::Array(vec![]),
    };
    obj(vec![("predicates", arr("predicates")), ("caveats", arr("caveats"))])
}

/// [`normalize_policy`] as the reference's exported function: `'predicates' in p` throws for a value that is not an object.
pub fn normalize_policy_checked(p: &Value) -> Result<Value, String> {
    if p.is_object() || p.is_array() {
        Ok(normalize_policy(p))
    } else {
        Err(format!("Cannot use 'in' operator to search for 'predicates' in {}", crate::intent_v2::js_value_string(p)))
    }
}

fn set_path(root: &mut Map<String, Value>, segs: &[&str], value: Value) {
    if segs.len() == 1 {
        root.insert(segs[0].to_string(), value);
        return;
    }
    let slot = root.entry(segs[0].to_string()).or_insert_with(|| Value::Object(Map::new()));
    if !slot.is_object() {
        *slot = Value::Object(Map::new());
    }
    if let Value::Object(m) = slot {
        set_path(m, &segs[1..], value);
    }
}

/// The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the verb space).
pub fn outcome_to_action(vs: &VerbSpace, o: &Value) -> Value {
    let mut params = Map::new();
    let mut env = Map::new();
    let mut subject = Map::new();
    let mut resource = ANY_RESOURCE.to_string();
    if let Some(values) = get(o, "values").and_then(Value::as_object) {
        for (path, value) in values {
            let segs: Vec<&str> = path.split('.').collect();
            if path == "action.resource" {
                resource = crate::intent_v2::js_value_string(value);
            } else if segs[0] == "action" && segs.len() > 2 && segs[1] == "params" {
                set_path(&mut params, &segs[2..], value.clone());
            } else if segs[0] == "env" && segs.len() > 1 {
                set_path(&mut env, &segs[1..], value.clone());
            } else if segs[0] == "subject" && segs.len() > 1 {
                set_path(&mut subject, &segs[1..], value.clone());
            }
        }
    }
    let mut a = Map::new();
    a.insert("verb".into(), get(o, "verb").cloned().unwrap_or(Value::Null));
    a.insert("resource".into(), Value::String(resource));
    a.insert("params".into(), Value::Object(params));
    a.insert("reversibilityClass".into(), vs.reversibility.as_ref().map(|r| jstr(r)).unwrap_or(Value::Null));
    if !env.is_empty() {
        a.insert("env".into(), Value::Object(env));
    }
    if !subject.is_empty() {
        a.insert("subject".into(), Value::Object(subject));
    }
    Value::Object(a)
}

/// A compiled admission oracle for one policy (compile once, query many times).
#[derive(Clone)]
pub struct Admitter {
    model: Value,
}

impl Admitter {
    pub fn new(policy: &Value) -> R<Admitter> {
        Ok(Admitter { model: crate::analyzer::to_model(policy)? })
    }
    /// Admission of a concrete outcome; an engine refusal is an `Err` (never read as an admit).
    pub fn admits(&self, vs: &VerbSpace, o: &Value) -> R<bool> {
        let d = crate::analyzer::decide_action_model(&self.model, &outcome_to_action(vs, o))?;
        Ok(d != "deny")
    }
}

pub fn admitter(policy: &Value) -> R<Admitter> {
    Admitter::new(policy)
}
