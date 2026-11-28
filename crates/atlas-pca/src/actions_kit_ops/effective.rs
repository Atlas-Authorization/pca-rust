//! T(d), decl(d) and eff_R(d) with a caller-supplied confirmation verifier, plus the structural param rules (effective.ts).

use super::{strs_of, Verifier};
use crate::actions::{
    closure, decl_profile, floor_of, hint_traits, implied_from_facts, join, normalize, top_traits, worst_reversibility, ActionKitError, ParamFacts, Profile,
    Registry, PARAM_RULE_IDS,
};
use serde_json::Value;

/// One view of a def: its traits, their closure and floor, and the effective profile (`decl` joined with the floor).
#[derive(Debug, Clone)]
pub struct View {
    pub traits: Vec<String>,
    pub closure: Vec<String>,
    pub floor: Profile,
    pub eff: Profile,
}

#[derive(Debug, Clone)]
pub struct Clamp {
    pub field: &'static str,
    pub declared: String,
    pub floor: String,
}

#[derive(Debug, Clone)]
pub struct EffectiveWith {
    pub confirmed: bool,
    pub main: View,
    pub decl: Profile,
    pub hint: View,
    pub clamps: Vec<Clamp>,
}

pub fn is_confirmed(d: &Value, v: Verifier) -> bool {
    v.is_some_and(|f| f(d))
}

pub fn implied_traits(n: &Value) -> Result<Vec<String>, String> {
    let params = n["params"].as_object().ok_or("params")?;
    let facts: Vec<ParamFacts> = params.values().map(ParamFacts::of).collect();
    implied_from_facts(&strs_of(n.get("effects")), &facts, n["resource"]["scope"].as_str(), &worst_reversibility(&n["reversibility"], params))
}

pub fn traits_of_with(d: &Value, reg: &Registry, v: Verifier) -> Vec<String> {
    if is_confirmed(d, v) {
        hint_traits(d)
    } else {
        top_traits(reg)
    }
}

fn rev_rank(r: &str) -> i32 {
    ["reversible", "rate_limited", "irreversible"].iter().position(|x| *x == r).map_or(0, |i| i as i32)
}

pub fn effective_with(d: &Value, reg: &Registry, v: Verifier) -> Result<EffectiveWith, ActionKitError> {
    let decl = decl_profile(d);
    let view = |traits: Vec<String>| -> Result<View, ActionKitError> {
        let floor = floor_of(reg, &traits)?;
        let cl = closure(reg, &traits)?;
        Ok(View { eff: join(&decl, &floor), floor, closure: cl, traits })
    };
    let hint = view(hint_traits(d))?;
    let confirmed = is_confirmed(d, v);
    let main = if confirmed { hint.clone() } else { view(top_traits(reg))? };
    let mut clamps = Vec::new();
    if d.get("reversibility").is_some() && rev_rank(&decl.rev) < rev_rank(&hint.floor.rev) {
        clamps.push(Clamp { field: "rev", declared: decl.rev.clone(), floor: hint.floor.rev.clone() });
    }
    if d.get("blast").is_some() && decl.blast_ppm < hint.floor.blast_ppm {
        clamps.push(Clamp { field: "blast_ppm", declared: decl.blast_ppm.to_string(), floor: hint.floor.blast_ppm.to_string() });
    }
    Ok(EffectiveWith { confirmed, main, decl, hint, clamps })
}

/// The hint profile after adding trait `t` to the declared traits (never lower). Analysis only.
pub fn eff_with_trait(d: &Value, t: &str, reg: &Registry) -> Result<Profile, ActionKitError> {
    let mut d2 = d.clone();
    let mut tr = strs_of(d.get("traits"));
    tr.push(t.to_string());
    d2["traits"] = super::jstrs(&tr);
    Ok(effective_with(&d2, reg, None)?.hint.eff)
}

/// Structural param rules (among `ids`) the def violates.
pub fn prules_violations(d: &Value, ids: &[String]) -> Vec<String> {
    let n = normalize(d);
    let params = n["params"].as_object().cloned().unwrap_or_default();
    let ps: Vec<&Value> = params.values().collect();
    let with_role = |pred: &dyn Fn(&str) -> bool| -> Vec<Value> {
        ps.iter().filter(|p| p.get("role").and_then(Value::as_str).is_some_and(pred)).map(|p| (*p).clone()).collect()
    };
    let money_ok = |p: &Value| -> bool {
        let Some(u) = p.get("unit").filter(|u| u.get("kind").and_then(Value::as_str) == Some("money")) else { return false };
        match u.get("ccy") {
            Some(Value::String(_)) => true,
            Some(c) => c.get("from").and_then(Value::as_str).and_then(|f| params.get(f)).is_some_and(|c| {
                c.get("role").and_then(Value::as_str) == Some("money.currency") && c.get("format").and_then(Value::as_str) == Some("iso_currency")
            }),
            None => false,
        }
    };
    let mut bad = Vec::new();
    for rid in ids {
        let ok = match rid.as_str() {
            "money_has_currency" => with_role(&|r| r == "money.amount" || r == "money.fee").iter().all(|p| money_ok(p)),
            "money_amount_bounded" => {
                with_role(&|r| r == "money.amount").iter().all(|p| p["type"] == "integer" && p.get("min").is_some() && p.get("max").is_some())
            }
            "id_not_wildcard" => !(n["resource"]["id"] == "*" && n["resource"]["scope"] == "one"),
            "recipient_param_declared" => {
                n.get("audience").and_then(Value::as_str) == Some("resource") || !with_role(&|r| r == "party.payee" || r.starts_with("contact.")).is_empty()
            }
            "array_bounded" => ps.iter().filter(|p| p["type"] == "array").all(|p| p.get("max_items").is_some_and(|m| !m.is_null())),
            "export_bounded" => n["resource"]["scope"] == "one" || with_role(&|r| r == "count.limit").iter().any(|p| p.get("max").is_some()),
            "secret_not_logged" => with_role(&|r| r.starts_with("credential.")).iter().all(|p| strs_of(p.get("tags")).iter().any(|t| t == "secret")),
            "pay_has_idempotency" => !strs_of(n.get("effects")).iter().any(|e| e == "pay") || n["idempotency"]["mode"] != "none",
            _ => true,
        };
        if !ok {
            bad.push(rid.clone());
        }
    }
    bad
}

/// All rule ids (the default of [`prules_violations`]).
pub fn all_prule_ids() -> Vec<String> {
    PARAM_RULE_IDS.iter().map(|s| s.to_string()).collect()
}
