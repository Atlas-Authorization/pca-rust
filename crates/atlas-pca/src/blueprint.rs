//! Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop
//! issued by that key. [`BlueprintRegistry`] keeps the newest record per key (pinned operators, a strictly higher epoch replaces,
//! the same epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies
//! (`ceiling_unevaluable`), so this verifier never allows past a ceiling it cannot read. Total: no function panics.
use crate::fresh_at::verify_body;
use crate::safe_int;
use serde_json::{Map, Value};
use std::collections::HashMap;

pub const AGENT_BLUEPRINT_DOMAIN: &str = "atlas-pca/agent-blueprint/v1\0";
const BODY_KEYS: [&str; 10] = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator"];

fn s(v: Option<&Value>, max: usize) -> Option<&str> {
    v.and_then(Value::as_str).filter(|x| !x.is_empty() && x.encode_utf16().count() <= max)
}
fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}

fn well_formed(v: &Value) -> Option<&Map<String, Value>> {
    let b = v.as_object()?;
    if b.get("v").and_then(safe_int) != Some(1) {
        return None;
    }
    s(b.get("id"), 128)?;
    s(b.get("key"), 128)?;
    s(b.get("operator"), 128)?;
    nat(b.get("epoch"))?;
    nat(b.get("issued_at"))?;
    if !matches!(b.get("status").and_then(Value::as_str), Some("active" | "disabled")) {
        return None;
    }
    if let Some(d) = b.get("max_depth") {
        if nat(Some(d)).filter(|n| *n >= 1).is_none() {
            return None;
        }
    }
    if let Some(e) = b.get("expires_at") {
        nat(Some(e))?;
    }
    let c = b.get("ceiling")?.as_array()?;
    if c.len() > 32 || !c.iter().all(|x| x.get("type").and_then(Value::as_str).is_some() && x.is_object()) {
        return None;
    }
    Some(b)
}

/// Well formed and signed by its `operator` over exactly its content.
pub fn verify_blueprint(v: &Value) -> bool {
    let Some(b) = well_formed(v) else { return false };
    let mut body = Map::new();
    for k in BODY_KEYS {
        if let Some(x) = b.get(k) {
            body.insert(k.to_string(), x.clone());
        }
    }
    let operator = b.get("operator").and_then(Value::as_str).unwrap_or("");
    verify_body(AGENT_BLUEPRINT_DOMAIN, &Value::Object(body), operator, b.get("sig").and_then(Value::as_str))
}

/// `Ok(replaced)` when taken, else the refusal code.
pub struct BlueprintRegistry {
    operators: Vec<String>,
    store: HashMap<String, Value>,
}

impl BlueprintRegistry {
    pub fn new(operators: Vec<String>) -> Self {
        Self { operators, store: HashMap::new() }
    }

    pub fn accept(&mut self, v: &Value) -> Result<bool, &'static str> {
        if !verify_blueprint(v) {
            return Err("bad_record");
        }
        let operator = v["operator"].as_str().unwrap_or("");
        if !self.operators.iter().any(|o| o == operator) {
            return Err("unknown_operator");
        }
        let key = v["key"].as_str().unwrap_or("").to_string();
        if let Some(cur) = self.store.get(&key) {
            if cur["operator"] != v["operator"] {
                return Err("operator_changed");
            }
            let (ce, be) = (nat(cur.get("epoch")).unwrap_or(0), nat(v.get("epoch")).unwrap_or(0));
            if be < ce {
                return Err("stale_epoch");
            }
            if be == ce {
                return if cur["sig"] == v["sig"] { Ok(false) } else { Err("epoch_fork") };
            }
        }
        self.store.insert(key, v.clone());
        Ok(true)
    }

    /// The highest epoch accepted so far (0 when empty).
    pub fn epoch(&self) -> i64 {
        self.store.values().filter_map(|r| nat(r.get("epoch"))).max().unwrap_or(0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlueprintDecision {
    /// `allow`, `deny` or `escalate`.
    pub decision: &'static str,
    pub code: Option<&'static str>,
    pub blueprint: Option<String>,
    pub governed: Vec<String>,
    pub have: i64,
    pub need: i64,
}

fn deny(code: &'static str, bp: Option<String>) -> BlueprintDecision {
    BlueprintDecision { decision: "deny", code: Some(code), blueprint: bp, ..Default::default() }
}

/// Gate a chain (`[{issuer, holder}]`, root first). `mode` is `require` or `any`; `min_epoch` is the `revocation_epoch` of the
/// newest `fresh_at` token the caller showed.
pub fn check_blueprints(chain: &Value, reg: &BlueprintRegistry, now: &Value, mode: &str, min_epoch: Option<i64>) -> BlueprintDecision {
    let (Some(hops), Some(now_ms)) = (chain.as_array(), nat(Some(now))) else { return deny("bad_input", None) };
    if hops.is_empty() {
        return deny("bad_input", None);
    }
    let mut hs: Vec<(&str, &str)> = Vec::new();
    for h in hops {
        match (s(h.get("issuer"), 128), s(h.get("holder"), 128)) {
            (Some(i), Some(o)) => hs.push((i, o)),
            _ => return deny("bad_input", None),
        }
    }
    if let Some(m) = min_epoch {
        if reg.epoch() < m {
            return BlueprintDecision { decision: "escalate", code: Some("stale_blueprint_state"), have: reg.epoch(), need: m, ..Default::default() };
        }
    }
    let mut governed = Vec::new();
    for (i, (issuer, _)) in hs.iter().enumerate() {
        let Some(bp) = reg.store.get(*issuer) else { continue };
        let id = bp["id"].as_str().unwrap_or("").to_string();
        if i == 0 || Some(hs[i - 1].1) != bp["key"].as_str() {
            return deny("broken_link", Some(id));
        }
        if bp["status"] != "active" {
            return deny("blueprint_disabled", Some(id));
        }
        if let Some(at) = bp.get("expires_at").and_then(safe_int) {
            if now_ms >= at {
                return deny("blueprint_expired", Some(id));
            }
        }
        if let Some(d) = bp.get("max_depth").and_then(safe_int) {
            if (hs.len() - i) as i64 > d {
                return deny("too_deep", Some(id));
            }
        }
        if bp["ceiling"].as_array().is_some_and(|c| !c.is_empty()) {
            return deny("ceiling_unevaluable", Some(id));
        }
        governed.push(id);
    }
    if governed.is_empty() && mode == "require" {
        return deny("no_blueprint", None);
    }
    BlueprintDecision { decision: "allow", governed, ..Default::default() }
}
