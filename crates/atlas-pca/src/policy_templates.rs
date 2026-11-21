//! Policy templates and a fluent authoring builder: a port of packages/pca/src/policy-templates.ts (the TypeScript is
//! authoritative). A request maps onto a named role template or is composed with [`PolicyBuilder`]; both compile through
//! [`create_agent`], so what you author is exactly what the verifier enforces.

use crate::agent::KeyPair;
use crate::facade::{create_agent, AgentHandle, AgentOptions};
use serde_json::{json, Map, Value};

/// A built-in role template: a conservative starting point, meant to be narrowed, not widened.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyTemplate {
    pub name: &'static str,
    pub description: &'static str,
    /// `{connector: [action, ...]}`.
    pub permissions: Value,
    /// `{verb | action: "50/day" | "$500/day"}`, when the template sets any.
    pub limits: Option<Value>,
    pub risk_policy: Option<Value>,
}

/// The built-in templates, in the reference's order.
pub fn list_templates() -> Vec<PolicyTemplate> {
    let t = |name, description, permissions, limits| PolicyTemplate { name, description, permissions, limits, risk_policy: None };
    vec![
        t(
            "read-only",
            "Read access only — no side effects anywhere.",
            json!({"github": ["read"], "slack": ["read"], "files": ["read"], "http": ["get"]}),
            None,
        ),
        t(
            "support-agent",
            "Draft + send customer email and post to Slack, rate-limited.",
            json!({"gmail": ["draft", "send"], "slack": ["post_message"]}),
            Some(json!({"send": "50/day", "post_message": "100/day"})),
        ),
        t("finance-bot", "Issue reversible refunds within a daily cap; no payouts.", json!({"stripe": ["refund"]}), Some(json!({"refund": "$500/day"}))),
        t(
            "dev-assistant",
            "Read repos, open PRs and comment — never merge or delete.",
            json!({"github": ["read", "create_pr", "comment"]}),
            Some(json!({"create_pr": "20/day"})),
        ),
    ]
}

fn template(name: &str) -> Option<PolicyTemplate> {
    list_templates().into_iter().find(|t| t.name == name)
}

fn unknown(who: &str, name: &str) -> String {
    let have: Vec<_> = list_templates().iter().map(|t| t.name).collect();
    format!("{who}: unknown template '{name}' (have: {})", have.join(", "))
}

/// Inputs of [`from_template`]. `overrides_*` replace the template's value (not a deep merge), as the reference does.
pub struct FromTemplateOptions<'a> {
    pub principal: &'a KeyPair,
    pub goal: &'a str,
    pub aud: Option<&'a str>,
    pub holder: Option<KeyPair>,
    pub now: Option<i64>,
    pub overrides_permissions: Option<&'a Value>,
    pub overrides_limits: Option<&'a Value>,
    pub overrides_risk_policy: Option<&'a Value>,
    pub agent_binding: Option<&'a Value>,
    pub budget_model: Option<&'a str>,
}

impl<'a> FromTemplateOptions<'a> {
    pub fn new(principal: &'a KeyPair, goal: &'a str) -> Self {
        Self {
            principal,
            goal,
            aud: None,
            holder: None,
            now: None,
            overrides_permissions: None,
            overrides_limits: None,
            overrides_risk_policy: None,
            agent_binding: None,
            budget_model: None,
        }
    }
}

/// Mint an agent from a named template. `Err` on an unknown template.
pub fn from_template(name: &str, o: FromTemplateOptions) -> Result<AgentHandle, String> {
    let t = template(name).ok_or_else(|| unknown("fromTemplate", name))?;
    let limits = o.overrides_limits.cloned().or(t.limits);
    let risk = o.overrides_risk_policy.cloned().or(t.risk_policy);
    let perms = o.overrides_permissions.cloned().unwrap_or(t.permissions);
    let mut a = AgentOptions::new(o.principal, o.goal, &perms);
    a.limits = limits.as_ref();
    a.risk_policy = risk.as_ref();
    a.agent_binding = o.agent_binding;
    a.budget_model = o.budget_model;
    a.aud = o.aud;
    a.holder = o.holder;
    a.now = o.now;
    create_agent(a)
}

/// The result of [`PolicyBuilder::build`].
#[derive(Clone, Debug, PartialEq)]
pub struct BuiltPolicy {
    pub permissions: Value,
    pub limits: Value,
    pub risk_policy: Option<Value>,
}

/// A chainable policy builder: `policy().allow("stripe", &["refund"]).limit("refund", "$500/day")`.
#[derive(Clone, Debug, Default)]
pub struct PolicyBuilder {
    perms: Map<String, Value>,
    lims: Map<String, Value>,
    risk: Option<Map<String, Value>>,
}

impl PolicyBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from a named template (its permissions, limits and risk seed the builder).
    pub fn from(name: &str) -> Result<Self, String> {
        let t = template(name).ok_or_else(|| unknown("PolicyBuilder.from", name))?;
        let mut b = Self::new();
        if let Some(m) = t.permissions.as_object() {
            for (c, acts) in m {
                let acts: Vec<&str> = acts.as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                b = b.allow(c, &acts);
            }
        }
        if let Some(m) = t.limits.as_ref().and_then(Value::as_object) {
            for (k, v) in m {
                b = b.limit(k, v.as_str().unwrap_or_default());
            }
        }
        if let Some(r) = t.risk_policy {
            b = b.risk(&r);
        }
        Ok(b)
    }

    /// Add actions to a connector (a set union: repeated actions collapse, order of first appearance kept).
    pub fn allow(mut self, connector: &str, actions: &[&str]) -> Self {
        let mut cur: Vec<Value> = self.perms.get(connector).and_then(Value::as_array).cloned().unwrap_or_default();
        for a in actions {
            if !cur.iter().any(|x| x.as_str() == Some(a)) {
                cur.push(Value::String((*a).into()));
            }
        }
        self.perms.insert(connector.into(), Value::Array(cur));
        self
    }

    pub fn limit(mut self, verb_or_action: &str, spec: &str) -> Self {
        self.lims.insert(verb_or_action.into(), Value::String(spec.into()));
        self
    }

    /// Merge risk-policy members over what is already set.
    pub fn risk(mut self, partial: &Value) -> Self {
        let r = self.risk.get_or_insert_with(Map::new);
        if let Some(p) = partial.as_object() {
            for (k, v) in p {
                r.insert(k.clone(), v.clone());
            }
        }
        self
    }

    pub fn build(&self) -> Result<BuiltPolicy, String> {
        if self.perms.is_empty() {
            return Err("PolicyBuilder: no permissions added".into());
        }
        Ok(BuiltPolicy {
            permissions: Value::Object(self.perms.clone()),
            limits: Value::Object(self.lims.clone()),
            risk_policy: self.risk.clone().map(Value::Object),
        })
    }

    /// Mint an agent directly from the built policy.
    pub fn agent(&self, principal: &KeyPair, goal: &str, aud: Option<&str>, holder: Option<KeyPair>, now: Option<i64>) -> Result<AgentHandle, String> {
        let b = self.build()?;
        let mut a = AgentOptions::new(principal, goal, &b.permissions);
        a.limits = Some(&b.limits);
        a.risk_policy = b.risk_policy.as_ref();
        a.aud = aud;
        a.holder = holder;
        a.now = now;
        create_agent(a)
    }
}

/// Entry point for the fluent builder.
pub fn policy() -> PolicyBuilder {
    PolicyBuilder::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_and_builder() {
        let names: Vec<_> = list_templates().iter().map(|t| t.name).collect();
        assert_eq!(names, ["read-only", "support-agent", "finance-bot", "dev-assistant"]);
        assert!(PolicyBuilder::from("nope").is_err());
        assert!(policy().build().is_err());
        let b = PolicyBuilder::from("finance-bot").unwrap().allow("stripe", &["refund", "void"]).limit("void", "5/day").build().unwrap();
        assert_eq!(b.permissions, json!({"stripe": ["refund", "void"]}));
        assert_eq!(b.limits, json!({"refund": "$500/day", "void": "5/day"}));
        let r = policy().allow("a", &["x"]).risk(&json!({"k": 1})).risk(&json!({"j": 2})).build().unwrap();
        assert_eq!(r.risk_policy, Some(json!({"k": 1, "j": 2})));
    }

    #[test]
    fn from_template_mints() {
        let p = KeyPair::generate().unwrap();
        let a = from_template("read-only", FromTemplateOptions::new(&p, "triage")).unwrap();
        assert_eq!(a.principal_public, p.public);
        assert!(from_template("nope", FromTemplateOptions::new(&p, "g")).err().is_some_and(|e| e.contains("unknown template 'nope'")));
    }
}
