//! Undo windows over action definitions, the structural and planning half (undo.ts): reversibility of a call, whether a def may
//! be reversible, the compensation shape, and the confirmation-gated undo engine.

use super::effective::{effective_with, is_confirmed};
use super::{int_of, isi, negzero, strs_of, u16cmp, Verifier};
use crate::actions::{def_digest, is_read_only, normalize, Registry};
use serde_json::{json, Map, Value};

/// The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible).
pub fn reversibility_for(d: &Value, params: &Value) -> String {
    let r = normalize(d)["reversibility"].clone();
    if let Some(s) = r.as_str() {
        return s.to_string();
    }
    let by = r["by"].as_str().unwrap_or("");
    let k: Option<String> = match params.get(by) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Bool(b)) => Some(b.to_string()),
        Some(v @ Value::Number(_)) if isi(v) && !negzero(v) => Some(int_of(v).to_string()),
        _ => None,
    };
    match k.and_then(|k| r["map"].get(&k).and_then(Value::as_str).map(String::from)) {
        Some(c) => c,
        None => r.get("default").and_then(Value::as_str).unwrap_or("irreversible").to_string(),
    }
}

/// True when some value of the declaration is `reversible` (a fixed class, a map value or the default).
pub fn may_be_reversible(d: &Value) -> bool {
    match d.get("reversibility") {
        None => false,
        Some(Value::String(s)) => s == "reversible",
        Some(r) => {
            r.get("map").and_then(Value::as_object).is_some_and(|m| m.values().any(|v| v == "reversible"))
                || r.get("default").and_then(Value::as_str) == Some("reversible")
        }
    }
}

fn same_type(a: Option<&Value>, b: &Value) -> bool {
    a.is_some_and(|a| a.get("type") == b.get("type") && a.get("items") == b.get("items"))
}

/// Can `comp` undo `orig` without the agent's help? `{ok: true, shape: {copied, target?}}` or `{ok: false, reason}`. Structural only.
pub fn compensation_shape(orig: &Value, comp: &Value) -> Value {
    let no = |r: String| json!({"ok": false, "reason": r});
    let cverb = comp["verb"].as_str().unwrap_or("");
    if is_read_only(&strs_of(comp.get("effects"))) {
        return no(format!("the compensating action {cverb} only reads"));
    }
    let (ct, ot) = (comp["resource"]["type"].as_str().unwrap_or(""), orig["resource"]["type"].as_str().unwrap_or(""));
    if ct != ot {
        return no(format!("the compensating action {cverb} acts on {ct}, not {ot}"));
    }
    let nc = normalize(comp);
    let idem = if nc["idempotency"]["mode"] == "key_param" { nc["idempotency"]["param"].as_str().map(String::from) } else { None };
    let mut names: Vec<&String> = nc["params"].as_object().map(|m| m.keys().collect()).unwrap_or_default();
    names.sort_by(|a, b| u16cmp(a, b));
    let (mut copied, mut target): (Vec<String>, Option<String>) = (vec![], None);
    for name in names {
        let p = &nc["params"][name];
        if idem.as_deref() == Some(name.as_str()) {
            continue;
        }
        if same_type(orig["params"].get(name), p) {
            copied.push(name.clone());
            continue;
        }
        if p["required"] != Value::Bool(true) {
            continue;
        }
        if target.is_none() && p.get("role").and_then(Value::as_str) == Some(format!("id.{ct}").as_str()) {
            target = Some(name.clone());
            continue;
        }
        return no(format!("the compensating action {cverb} needs '{name}', which neither the original call nor its result supplies"));
    }
    let mut shape = Map::new();
    shape.insert("copied".into(), json!(copied));
    if let Some(t) = target {
        shape.insert("target".into(), json!(t));
    }
    json!({"ok": true, "shape": shape})
}

/// The confirmation-gated plan: answers only from CONFIRMED definitions (no verifier: nothing is undoable), exact verb match only.
pub struct UndoEngine<'a> {
    by_verb: std::collections::BTreeMap<String, Value>,
    reg: &'a Registry,
    verifier: Verifier<'a>,
}

pub fn undo_engine<'a>(defs: &[Value], reg: &'a Registry, verifier: Verifier<'a>) -> UndoEngine<'a> {
    let mut by_verb = std::collections::BTreeMap::new();
    for d in defs {
        if let Some(v) = d.get("verb").and_then(Value::as_str) {
            by_verb.entry(v.to_string()).or_insert_with(|| d.clone());
        }
    }
    UndoEngine { by_verb, reg, verifier }
}

impl UndoEngine<'_> {
    fn confirmed(&self, d: &Value) -> bool {
        is_confirmed(d, self.verifier)
    }

    /// `{def_digest, compensation, render, render_digest}` or `None` (never undoable). Never panics on a hostile op.
    pub fn plan(&self, op: &Value) -> Option<Value> {
        let d = self.by_verb.get(op.get("verb")?.as_str()?)?;
        let params = match op.get("params") {
            None | Some(Value::Null) => json!({}),
            Some(p) if p.is_object() => p.clone(),
            Some(_) => return None, // fail closed: params that are not an object
        };
        if !self.confirmed(d) || is_read_only(&strs_of(d.get("effects"))) {
            return None;
        }
        let cv = d.get("compensates")?.as_str()?;
        if effective_with(d, self.reg, self.verifier).ok()?.main.eff.rev != "reversible" || reversibility_for(d, &params) != "reversible" {
            return None;
        }
        let c = self.by_verb.get(cv)?;
        if !self.confirmed(c) {
            return None;
        }
        let s = compensation_shape(d, c);
        if s["ok"] != Value::Bool(true) {
            return None;
        }
        let nc = normalize(c);
        let mut cparams = Map::new();
        for k in s["shape"]["copied"].as_array()? {
            let k = k.as_str()?;
            if let Some(v) = params.get(k) {
                cparams.insert(k.to_string(), v.clone());
            } else if nc["params"][k]["required"] == Value::Bool(true) {
                return None;
            }
        }
        let render = crate::approval::render_approval(d, &params, true).ok()?;
        let mut comp = Map::new();
        comp.insert("verb".into(), c["verb"].clone());
        comp.insert("params".into(), Value::Object(cparams));
        comp.insert("def_digest".into(), json!(def_digest(c)?));
        if let Some(t) = s["shape"].get("target") {
            comp.insert("target_param".into(), t.clone());
        }
        Some(
            json!({"def_digest": def_digest(d)?, "compensation": comp, "render_digest": crate::approval::approval_render_digest(&render).ok()?, "render": render}),
        )
    }
}
