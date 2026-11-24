//! Server-side risk inputs from the connector action catalog (port of packages/pca/src/catalog-risk.ts over the 21 built-in reviewed
//! actions of catalog-builtin.generated.ts).
//!
//! The verifier prices every risk input the server does not supply at the worst case, so a server that supplies none sends every
//! non-money tool to a co-sign. [`catalog_risk`] returns the inputs a server can vouch for from its own data: the catalogue's
//! reversibility class and blast radius for the verb, and for a money-moving verb the blast radius `amount / kappa` from the operation's
//! (verified) amount and the grant's signed risk policy. It never reads anything the agent claims.
use crate::authorize::read_envelope;
use serde_json::{json, Map, Value};

/// `(verb, reversibility, blast radius, amount field)` of the built-in catalogue (generated from the reviewed action definitions).
pub const BUILTIN_CATALOG: [(&str, &str, f64, Option<&str>); 21] = [
    ("stripe.charge", "irreversible", 0.9, Some("amount")),
    ("stripe.refund", "irreversible", 0.9, Some("amount")),
    ("stripe.payout", "irreversible", 0.9, Some("amount")),
    ("stripe.create_customer", "rate_limited", 0.2, None),
    ("gmail.send", "irreversible", 0.8, None),
    ("gmail.draft", "reversible", 0.2, None),
    ("gmail.delete", "irreversible", 0.8, None),
    ("github.read", "reversible", 0.05, None),
    ("github.create_pr", "irreversible", 0.2, None),
    ("github.comment", "irreversible", 0.2, None),
    ("github.merge_pr", "irreversible", 0.5, None),
    ("github.delete_repo", "irreversible", 0.8, None),
    ("slack.post_message", "irreversible", 0.5, None),
    ("slack.read", "reversible", 0.05, None),
    ("calendar.create_event", "irreversible", 0.2, None),
    ("calendar.delete_event", "rate_limited", 0.5, None),
    ("files.read", "reversible", 0.05, None),
    ("files.write", "rate_limited", 0.5, None),
    ("files.delete", "irreversible", 0.8, None),
    ("http.get", "reversible", 0.05, None),
    ("http.post", "rate_limited", 0.5, None),
];

/// `(verb, aliases)` of the built-in actions that answer to other names (`refund` for `stripe.refund`); the facade resolves a
/// permission through them when the alias names exactly one action of the connector.
pub const BUILTIN_ALIASES: [(&str, &[&str]); 4] = [
    ("stripe.charge", &["bill", "charge_customer"]),
    ("stripe.refund", &["issue_refund", "refund", "refund_charge", "reimburse"]),
    ("stripe.payout", &["pay_out", "payout"]),
    ("gmail.send", &["send_email"]),
];

/// Reversibility score per class (1 = fully reversible), the scale the hosted adjudicator uses.
pub fn reversibility_score(class: &str) -> Option<f64> {
    match class {
        "reversible" => Some(1.0),
        "rate_limited" | "costly" => Some(0.4),
        "irreversible" => Some(0.0),
        _ => None,
    }
}

fn unit(x: f64) -> f64 {
    let lo = if 0.0 > x { 0.0 } else { x };
    if 1.0 < lo { 1.0 } else { lo }
}

/// Risk inputs for `verb` with `params`, from the catalogue and the grant. An unknown verb returns `{}` (every input is then priced at
/// the worst case). A money-moving verb whose amount is missing or not a finite number >= 0, or whose grant has no positive `kappa`,
/// gets blast radius 1. `taint` is the server-observed taint of the operation's inputs in [0, 1] (absent: priced at the worst case).
pub fn catalog_risk(verb: &str, params: &Value, grant: &Value, taint: Option<f64>) -> Map<String, Value> {
    let Some((_, class, blast, amount_field)) = BUILTIN_CATALOG.iter().find(|r| r.0 == verb) else { return Map::new() };
    let reversibility = reversibility_score(class).unwrap_or(0.0);
    let mut blast_radius = unit(*blast);
    if let Some(field) = amount_field {
        let amount = params.as_object().and_then(|m| m.get(*field)).filter(|v| v.is_number()).and_then(Value::as_f64).filter(|a| a.is_finite() && *a >= 0.0);
        let kappa = read_envelope(grant).and_then(|e| e.get("risk_policy").and_then(|p| p.get("kappa")).and_then(Value::as_f64)).filter(|k| *k > 0.0);
        blast_radius = match (amount, kappa) {
            (Some(a), Some(k)) => unit(a / k),
            _ => 1.0,
        };
    }
    let mut out = Map::new();
    out.insert("reversibility".into(), json!(reversibility));
    out.insert("blastRadius".into(), json!(blast_radius));
    out.insert("confidence".into(), json!(1));
    if let Some(t) = taint.filter(|t| t.is_finite()) {
        out.insert("taint".into(), json!(unit(t)));
    }
    out
}

#[cfg(test)]
#[path = "k05f_catalog_risk_test.rs"]
mod k05f_catalog_risk_test;
