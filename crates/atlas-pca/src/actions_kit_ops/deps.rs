//! The one seam between this directory and the rest of the action kit that the authoring side owns (`actions_kit`): derive (schema
//! documents, operations, policy cards) and diff. Each wrapper has a plain JSON-valued shape; adapt the call here and nowhere else.

use super::Verifier;
use crate::actions::Registry;
use serde_json::{Map, Value};

/// The semantic diff of two defs under a registry and a confirmation verifier: `{class, reasons}`.
pub fn diff_defs(old: &Value, new: &Value, reg: &Registry, v: Verifier) -> Result<Value, String> {
    crate::actions_kit::diff::diff_defs(old, new, reg, v)
}

/// The unsigned v2 schema document of a set of defs (`meta`: `{site, aud, version, pack?}`).
pub fn to_schema_doc(defs: &[Value], reg: &Registry, meta: &Value) -> Result<Value, String> {
    crate::actions_kit::derive::to_schema_doc(defs, reg, meta, None)
}

/// `{verb, units}`: the signed v2 verb declaration of a def and the units it needs.
pub fn to_schema_verb(def: &Value, reg: &Registry) -> Result<Value, String> {
    crate::actions_kit::derive::to_schema_verb(def, reg, None)
}

/// `{ok: true, op: {verb, resource, params}}` or `{ok: false, reason}` for the call's `params` object.
pub fn operation_of(def: &Value, call_params: &Value) -> Value {
    crate::actions_kit::derive::operation_of(def, call_params)
}

/// The policy card of a def as the reviewer sees it: the HINT view (declared and implied traits) counted as confirmed.
pub fn card_of_shown(def: &Value, reg: &Registry) -> Result<Value, String> {
    let mut e = crate::actions_kit::effective_with(def, reg, None)?;
    e.main = e.hint.clone();
    e.confirmed = true;
    crate::actions_kit::derive::card_of(def, &e, reg)
}

/// Nested plain objects become dotted keys (up to 3 segments); arrays and scalars are leaves; a deeper object stays a leaf.
pub fn flatten_params(params: &Value) -> Map<String, Value> {
    fn walk(out: &mut Map<String, Value>, prefix: &str, depth: usize, v: &Value) {
        match v.as_object().filter(|o| depth < 3 && !o.is_empty()) {
            Some(o) => {
                for (k, x) in o {
                    let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    walk(out, &p, depth + 1, x);
                }
            }
            None => {
                out.insert(prefix.to_string(), v.clone());
            }
        }
    }
    let mut out = Map::new();
    for (k, v) in params.as_object().into_iter().flatten() {
        walk(&mut out, k, 1, v);
    }
    out
}
