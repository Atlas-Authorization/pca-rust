//! Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop
//! issued by that key. [`BlueprintRegistry`] keeps the newest record per key (pinned operators, a strictly higher epoch replaces,
//! the same epoch with different content is a fork). A non-empty ceiling is never evaluated here: it denies
//! (`ceiling_unevaluable`), so this verifier never allows past a ceiling it cannot read. Admission is not implemented here: a
//! record with `runtime_pins` is accepted and denies (`admission_required`), never falls through. Total: no function panics.
use crate::fresh_at::verify_body;
use crate::safe_int;
use serde_json::{Map, Value};
use std::collections::HashMap;

pub const AGENT_BLUEPRINT_DOMAIN: &str = "atlas-pca/agent-blueprint/v1\0";
const BODY_KEYS: [&str; 11] = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator"];
const PIN_KEYS: [&str; 5] = ["runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id"];

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
    if let Some(p) = b.get("runtime_pins") {
        let pins = p.as_array()?;
        let ok = |x: &Value| x.as_object().is_some_and(|o| !o.is_empty() && o.iter().all(|(k, v)| PIN_KEYS.contains(&k.as_str()) && s(Some(v), 256).is_some()));
        if pins.is_empty() || pins.len() > 16 || !pins.iter().all(ok) {
            return None;
        }
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
        if bp.get("runtime_pins").is_some() {
            return deny("admission_required", Some(id));
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

#[cfg(test)]
mod runtime_pins_tests {
    use super::*;
    use crate::agent::KeyPair;
    use crate::attest::util::b64url_enc;
    use crate::fresh_at::domain_bytes;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000_000;

    fn op() -> KeyPair {
        KeyPair::from_seed(&[5u8; 32])
    }
    /// A record signed over every member given (`bp-key`, active, epoch 1 unless overridden).
    fn signed(over: Value) -> Value {
        let mut b = json!({"v": 1, "id": "fleet", "key": "bp-key", "ceiling": [], "epoch": 1, "status": "active", "issued_at": NOW, "operator": op().public});
        for (k, v) in over.as_object().unwrap() {
            b[k] = v.clone();
        }
        let sig = b64url_enc(&op().sign(&domain_bytes(AGENT_BLUEPRINT_DOMAIN, &b).unwrap()));
        b["sig"] = json!(sig);
        b
    }
    fn pinned(extra: Value) -> Value {
        let mut o = json!({"runtime_pins": [{"runtime_measurement": "rt-1", "operator": "acme"}]});
        for (k, v) in extra.as_object().unwrap() {
            o[k] = v.clone();
        }
        signed(o)
    }
    fn chain(depth_below: usize) -> Value {
        let mut hops = vec![json!({"issuer": "root", "holder": "bp-key"}), json!({"issuer": "bp-key", "holder": "inst"})];
        hops.extend((0..depth_below).map(|_| json!({"issuer": "inst", "holder": "inst"})));
        Value::Array(hops)
    }
    fn code(rec: &Value, depth_below: usize, mode: &str) -> Option<&'static str> {
        let mut reg = BlueprintRegistry::new(vec![op().public]);
        assert_eq!(reg.accept(rec), Ok(true));
        check_blueprints(&chain(depth_below), &reg, &json!(NOW), mode, None).code
    }

    /// blueprint.ts:202-205: this verifier has no admission check, so a pinned record denies in both modes, never falls through.
    #[test]
    fn a_pinned_blueprint_is_accepted_then_denied() {
        let rec = pinned(json!({}));
        assert!(verify_blueprint(&rec));
        for mode in ["require", "any"] {
            let mut reg = BlueprintRegistry::new(vec![op().public]);
            assert_eq!(reg.accept(&rec), Ok(true));
            let d = check_blueprints(&chain(0), &reg, &json!(NOW), mode, None);
            assert_eq!((d.decision, d.code, d.blueprint.as_deref()), ("deny", Some("admission_required"), Some("fleet")), "{mode}");
        }
        // Without pins the same chain is allowed: the pins are what denies.
        assert_eq!(code(&signed(json!({})), 0, "any"), None);
    }

    /// The order of blueprint.ts:198-205: status, expiry and depth first, then the pins, then the ceiling.
    #[test]
    fn the_pins_are_checked_at_the_reference_position() {
        assert_eq!(code(&pinned(json!({"status": "disabled", "epoch": 2})), 0, "any"), Some("blueprint_disabled"));
        assert_eq!(code(&pinned(json!({"expires_at": NOW})), 0, "any"), Some("blueprint_expired"));
        assert_eq!(code(&pinned(json!({"max_depth": 1})), 1, "any"), Some("too_deep"));
        assert_eq!(code(&pinned(json!({"ceiling": [{"type": "expires", "at": NOW}]})), 0, "any"), Some("admission_required"));
    }

    /// The signature covers the pins: dropping or editing them breaks the record.
    #[test]
    fn the_pins_are_signed() {
        let rec = pinned(json!({}));
        let mut stripped = rec.clone();
        stripped.as_object_mut().unwrap().remove("runtime_pins");
        assert!(!verify_blueprint(&stripped));
        let mut edited = rec.clone();
        edited["runtime_pins"][0]["operator"] = json!("other");
        assert!(!verify_blueprint(&edited));
    }

    /// blueprint.ts:86-90: 1 to 16 pins, each a non-empty object of known keys holding strings of 1 to 256 UTF-16 units.
    #[test]
    fn pin_shapes() {
        let with = |p: Value| verify_blueprint(&signed(json!({"runtime_pins": p})));
        let many = |n: usize| Value::Array(vec![json!({"operator": "a"}); n]);
        for k in ["runtime_measurement", "model_id", "weights_digest", "operator", "spiffe_id"] {
            assert!(with(json!([{ k: "a" }])), "{k}");
        }
        assert!(with(many(16)));
        assert!(with(json!([{"operator": "a".repeat(256)}])));
        assert!(with(json!([{"operator": "\u{1F600}".repeat(128)}])));
        for bad in [
            many(0),
            many(17),
            Value::Null,
            json!({"operator": "a"}),
            json!([{}]),
            json!([{"bogus": "x"}]),
            json!([{"operator": "a", "bogus": "x"}]),
            json!([{"operator": ""}]),
            json!([{"operator": 1}]),
            json!([{"operator": "a".repeat(257)}]),
            json!([{"operator": "\u{1F600}".repeat(129)}]),
            json!(["operator"]),
            json!([{"operator": "a"}, {}]),
        ] {
            assert!(!with(bad.clone()), "{bad}");
        }
    }

    /// blueprint.ts:92: at most 32 ceiling entries, each an object with a string `type`, every record validly signed.
    #[test]
    fn ceiling_shapes() {
        let with = |c: Value| verify_blueprint(&signed(json!({"ceiling": c})));
        let many = |n: usize| Value::Array(vec![json!({"type": "expires", "at": NOW}); n]);
        assert!(with(many(1)));
        assert!(with(many(32)));
        assert!(!with(many(33)));
        for bad in [json!([{"at": NOW}]), json!([{"type": 1}]), json!([1]), json!(["expires"]), json!([[]]), json!([{"type": "expires"}, {}])] {
            assert!(!with(bad.clone()), "{bad}");
        }
    }

    /// blueprint.ts:82 with sig.ts isStr: 1 to 128 UTF-16 units.
    #[test]
    fn id_length() {
        let with = |id: String| verify_blueprint(&signed(json!({"id": id})));
        assert!(with("a".repeat(128)));
        assert!(with("\u{1F600}".repeat(64)));
        assert!(!with(String::new()));
        assert!(!with("a".repeat(129)));
        assert!(!with("\u{1F600}".repeat(65)));
    }

    /// blueprint.ts:113,146,190: the epoch is the highest accepted across keys, 0 when empty, and what a caller's minEpoch compares to.
    #[test]
    fn registry_epoch_is_the_highest_accepted() {
        let mut reg = BlueprintRegistry::new(vec![op().public]);
        assert_eq!(reg.epoch(), 0);
        assert_eq!(reg.accept(&signed(json!({"epoch": 5}))), Ok(true));
        assert_eq!(reg.accept(&signed(json!({"key": "bp-2", "epoch": 3}))), Ok(true));
        assert_eq!(reg.epoch(), 5);
        let stale = check_blueprints(&chain(0), &reg, &json!(NOW), "any", Some(6));
        assert_eq!((stale.decision, stale.code, stale.have, stale.need), ("escalate", Some("stale_blueprint_state"), 5, 6));
        assert_eq!(check_blueprints(&chain(0), &reg, &json!(NOW), "any", Some(5)).decision, "allow");
    }
}
