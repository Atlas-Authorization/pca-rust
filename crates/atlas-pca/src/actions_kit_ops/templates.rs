//! Starter packs a platform can begin from (templates.ts): typical actions of five business types in the authoring YAML form, with
//! custom traits and business rules. Every action is an authored draft: a template never confirms anything. The data is generated
//! from the reference (`templates_data.json`); the namespace is substituted into it.

use super::kerr;
use crate::actions::ActionKitError;
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

const DATA: &str = include_str!("templates_data.json");

fn data() -> &'static Value {
    static D: OnceLock<Value> = OnceLock::new();
    D.get_or_init(|| serde_json::from_str(DATA).expect("templates_data.json"))
}

fn marker() -> &'static str {
    data()["marker"].as_str().unwrap_or("zzmarkerzz")
}

/// The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`.
pub fn check_ns(ns: &Value) -> Result<String, ActionKitError> {
    static R: OnceLock<Regex> = OnceLock::new();
    let re = R.get_or_init(|| Regex::new(r"^[a-z][a-z0-9_]{0,31}$").unwrap());
    let Some(s) = ns.as_str().filter(|s| re.is_match(s)) else {
        return Err(kerr("bad_ns", "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)"));
    };
    if s == "pca" {
        return Err(kerr("bad_ns", "the namespace 'pca' is reserved for core traits"));
    }
    Ok(s.to_string())
}

fn sub(x: &Value, ns: &str) -> Value {
    match x {
        Value::String(s) => Value::String(s.replace(marker(), ns)),
        Value::Array(a) => Value::Array(a.iter().map(|v| sub(v, ns)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), sub(v, ns))).collect()),
        v => v.clone(),
    }
}

/// One starter template (`id`, `title`, `description`, default `ns`).
#[derive(Debug, Clone)]
pub struct StarterTemplate {
    raw: &'static Value,
}

impl StarterTemplate {
    pub fn id(&self) -> &str {
        self.raw["id"].as_str().unwrap_or("")
    }
    pub fn title(&self) -> &str {
        self.raw["title"].as_str().unwrap_or("")
    }
    pub fn description(&self) -> &str {
        self.raw["description"].as_str().unwrap_or("")
    }
    pub fn ns(&self) -> &str {
        self.raw["ns"].as_str().unwrap_or("")
    }
    /// The pack's custom traits under namespace `ns` (ids `<ns>.<name>`).
    pub fn traits(&self, ns: &str) -> Result<Value, ActionKitError> {
        Ok(sub(&self.raw["traits"], &check_ns(&Value::String(ns.into()))?))
    }
    /// The authoring YAML under namespace `ns`, with `rules:` blocks and their examples.
    pub fn yaml(&self, ns: &str) -> Result<String, ActionKitError> {
        Ok(self.raw["yaml"].as_str().unwrap_or("").replace(marker(), &check_ns(&Value::String(ns.into()))?))
    }
}

pub fn starter_templates() -> Vec<StarterTemplate> {
    data()["templates"].as_array().into_iter().flatten().map(|raw| StarterTemplate { raw }).collect()
}

pub fn starter_template(id: &str) -> Option<StarterTemplate> {
    starter_templates().into_iter().find(|t| t.id() == id)
}
