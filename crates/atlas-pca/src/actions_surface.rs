//! The public constants, grammars and small helpers of the action kit (packages/pca-actions: def.ts, core-traits.ts,
//! normalize.ts, traits.ts, pack.ts, rule22.ts, builtin-review.ts, approval-profiles.ts), under the reference's names in
//! snake case. The TypeScript is authoritative. The `*_RE` constants hold the reference's regular expression source; the
//! `is_*` functions are the exact matchers (hand-written: those patterns are outside the linear-time matcher's dialect).

use crate::actions::{core_registry, join, Profile, TraitDef, ROLE_SENS, TABLE, TAG_SENS};
use crate::approval::{approval_render_digest, binding_words, minor_to_decimal, psd2_linking};
use serde_json::{json, Value};

pub use crate::actions::pack_verify as verify_pack_proof;
pub use crate::actions_registry::{rule22_decide, rule22_integrity};
pub use crate::actions_registry::{rules_digest as pack_rules_digest, verify_pack as verify_action_pack};

pub const ACTION_PACK_KIND: &str = "pca-action-pack";
pub const ACTION_DEF_VERSION: i64 = 1;
pub const MAX_EVOLUTION_RECORDS: usize = 65_536;
pub const DEFAULT_RULES_VERSION: &str = "1.1.0";
pub const CORE_NAMESPACE: &str = "pca.";
pub const PARAM_TYPES_V1: [&str; 9] = ["string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"];
pub const SENSITIVITY_LEVELS: [&str; 3] = ["free", "material", "critical"];
/// `{hour, day}` in milliseconds.
pub const RATE_PERIODS: [(&str, i64); 2] = [("hour", 3_600_000), ("day", 86_400_000)];
/// Sensitivity floor per core role, and per param tag.
pub const ROLE_SENSITIVITY_FLOOR: [(&str, &str); 17] = ROLE_SENS;
pub const TAG_SENSITIVITY_FLOOR: [(&str, &str); 9] = TAG_SENS;

pub const ID_ROLE_RE: &str = r"^id\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$";
pub const CUSTOM_ROLE_RE: &str = r"^x\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}$";
pub const ID_FORMAT_RE: &str = r"^id:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}$";
pub const TAINT_CONTEXT_RE: &str = r"^session_taint_max:[a-z_]{1,16}$";
pub const VERB_RE: &str = r"^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}$";
pub const ALIAS_RE: &str = r"^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}$";
pub const PARAM_NAME_RE: &str = r"^[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}$";
pub const TRAIT_ID_RE: &str = r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$";
pub const RESOURCE_TYPE_RE: &str = r"^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}$";
/// The import namespace grammar (import/common.ts).
pub const NS_RE: &str = r"^[a-z][a-z0-9_]{0,31}$";

fn low(c: u8) -> bool {
    c.is_ascii_lowercase()
}
fn word(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'
}
fn word_ci(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}
/// `s` is `min..=max` bytes of `ok`.
fn run(s: &str, min: usize, max: usize, ok: fn(u8) -> bool) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(ok)
}
/// `[a-z][a-z0-9_]{0,tail}`.
fn head(s: &str, tail: usize) -> bool {
    s.as_bytes().first().is_some_and(|c| low(*c)) && run(&s[1..], 0, tail, word)
}
/// `head` then `lo..=hi` dotted tails of `[a-z0-9_]{1,32}`.
fn dotted(s: &str, tail_max: usize, lo: usize, hi: usize) -> bool {
    let mut it = s.split('.');
    let first = it.next().unwrap_or("");
    let rest: Vec<&str> = it.collect();
    head(first, tail_max) && (lo..=hi).contains(&rest.len()) && rest.iter().all(|p| run(p, 1, 32, word))
}
fn plus_segments(s: &str, lo: usize, hi: usize) -> bool {
    let ps: Vec<&str> = s.split('.').collect();
    (lo..=hi).contains(&ps.len()) && ps.iter().all(|p| run(p, 1, usize::MAX, word))
}

pub fn is_id_role(s: &str) -> bool {
    s.strip_prefix("id.").is_some_and(|r| plus_segments(r, 1, 4))
}
pub fn is_custom_role(s: &str) -> bool {
    s.strip_prefix("x.").is_some_and(|r| plus_segments(r, 2, 4))
}
pub fn is_id_format(s: &str) -> bool {
    s.strip_prefix("id:").is_some_and(|r| plus_segments(r, 1, 4))
}
pub fn is_taint_context(s: &str) -> bool {
    s.strip_prefix("session_taint_max:").is_some_and(|r| run(r, 1, 16, |c| c.is_ascii_lowercase() || c == b'_'))
}
pub fn is_verb(s: &str) -> bool {
    dotted(s, 31, 1, 5)
}
pub fn is_alias(s: &str) -> bool {
    dotted(s, 31, 0, 5)
}
pub fn is_param_name(s: &str) -> bool {
    let ps: Vec<&str> = s.split('.').collect();
    (1..=3).contains(&ps.len()) && ps.iter().all(|p| run(p, 1, 64, word_ci))
}
pub fn is_trait_id(s: &str) -> bool {
    s.split_once('.').is_some_and(|(a, b)| head(a, 31) && head(b, 63))
}
pub fn is_resource_type(s: &str) -> bool {
    dotted(s, 31, 0, 4)
}
pub fn is_ns(s: &str) -> bool {
    head(s, 31)
}

/// Sensitivity rank: free 0, material 1, critical 2.
pub fn sensitivity_rank(level: &str) -> Option<u8> {
    SENSITIVITY_LEVELS.iter().position(|l| *l == level).map(|i| i as u8)
}

/// Rank of a decision: deny 0, escalate 1, allow 2.
pub fn decision_rank(d: &str) -> Option<u8> {
    ["deny", "escalate", "allow"].iter().position(|x| *x == d).map(|i| i as u8)
}

fn lookup(t: &[(&'static str, &'static str)], k: &str) -> Option<&'static str> {
    t.iter().find(|(n, _)| *n == k).map(|(_, v)| *v)
}
fn max_sens(a: &'static str, b: &'static str) -> &'static str {
    if sensitivity_rank(a) >= sensitivity_rank(b) {
        a
    } else {
        b
    }
}

/// The sensitivity floor a param's role and tags impose (`free` when neither names one).
pub fn sensitivity_floor(role: Option<&str>, tags: &[&str]) -> &'static str {
    let mut f = "free";
    if let Some(s) = role.and_then(|r| lookup(&ROLE_SENS, r)) {
        f = max_sens(f, s);
    }
    for t in tags {
        if let Some(s) = lookup(&TAG_SENS, t) {
            f = max_sens(f, s);
        }
    }
    f
}

/// The effective sensitivity: the declared value (default `free`), raised to the floor. An unknown declared level counts as `free`.
pub fn effective_param_sensitivity(role: Option<&str>, tags: &[&str], declared: Option<&str>) -> &'static str {
    let d = declared.and_then(|d| SENSITIVITY_LEVELS.iter().copied().find(|l| *l == d)).unwrap_or("free");
    max_sens(d, sensitivity_floor(role, tags))
}

/// The core trait ids in the reference's table order.
pub fn core_trait_ids() -> Vec<String> {
    TABLE.iter().map(|r| format!("{CORE_NAMESPACE}{}", r.0)).collect()
}

/// The core trait definitions in table order.
pub fn core_trait_defs() -> Vec<TraitDef> {
    let reg = core_registry();
    core_trait_ids().iter().filter_map(|id| reg.traits.get(id).cloned()).collect()
}

/// The join of `ps` over the bottom profile.
pub fn join_all(ps: &[Profile]) -> Profile {
    ps.iter().fold(Profile::bottom(), |a, p| join(&a, p))
}

/// The characters of an id class (`digits`, `hex`, `alnum`, `slug`, `uuid`, `any_safe`).
pub fn id_class_chars(class: &str) -> Option<String> {
    const ALNUM: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    Some(match class {
        "digits" => "0123456789".into(),
        "hex" => "0123456789abcdef".into(),
        "alnum" => ALNUM.into(),
        "slug" => "0123456789abcdefghijklmnopqrstuvwxyz-_".into(),
        "uuid" => "0123456789abcdef-".into(),
        "any_safe" => format!("{ALNUM}._-:/"),
        _ => return None,
    })
}

// ---- rule 22 ----------------------------------------------------------------------------------------------------------------

/// The trait engine the verifier's rule 22 calls (the reference's `RULE22_ENGINE`): integrity of a document's floors and the
/// decision of a verb's floors against a grant and the call context.
#[derive(Clone, Copy, Debug)]
pub struct Rule22Engine;

pub const RULE22_ENGINE: Rule22Engine = Rule22Engine;

impl Rule22Engine {
    /// `None` when the document's traits and materialized floors are what the registry derives; else the refusal reason.
    pub fn schema_error(&self, doc: &Value, reviewers: Option<&Value>) -> Option<String> {
        crate::actions::schema_floor_error(doc, reviewers)
    }
    /// `allow`, `escalate` or `deny`; anything malformed denies.
    pub fn decide(&self, doc: &Value, verb: &str, grant: &Value, context: &Value) -> &'static str {
        rule22_decide(doc, verb, grant, context)
    }
}

// ---- built-in release attestation -------------------------------------------------------------------------------------------

/// The release pins the built-in attestations verify against: this package carries none (the built-ins stay unconfirmed), so `None`.
pub fn builtin_release_ctx() -> Option<Value> {
    None
}

/// The review options under which released built-ins count as confirmed: no verifier without release pins.
pub fn builtin_review_opts<'a>() -> Option<Box<dyn Fn(&Value) -> bool + 'a>> {
    None
}

// ---- approval profiles ----------------------------------------------------------------------------------------------------------

/// The SPC expectation for a payment render: `{topOrigin, total: {currency, value}, payeeName | payeeOrigin}`.
pub fn spc_expectation(render: &Value, top_origin: &str, payee_as_origin: bool) -> Result<Value, String> {
    let l = psd2_linking(render).map_err(|e| e.message)?;
    let minor = l["amount_minor"].as_i64().ok_or("psd2_unlinkable: the amount must be a non-negative integer in minor units")?;
    let exp = l["exp"].as_i64().ok_or("psd2_unlinkable: the exponent must be an integer")?;
    let value = minor_to_decimal(minor, exp).map_err(|e| e.message)?;
    let mut o = json!({"topOrigin": top_origin, "total": {"currency": l["currency"], "value": value}});
    o[if payee_as_origin { "payeeOrigin" } else { "payeeName" }] = l["payee"].clone();
    Ok(o)
}

/// The RFC 9396 `authorization_details` entry carrying the canonical render, plus the speakable match code.
pub fn ciba_approval_details(render: &Value) -> Result<Value, String> {
    let render_digest = approval_render_digest(render)?;
    let match_code = binding_words(&render_digest)?;
    Ok(json!({"authorization_details": [{"type": "pca_approval", "render": render, "render_digest": render_digest}], "match_code": match_code}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammars() {
        assert!(is_verb("a.b") && is_verb("pay.invoice.create") && !is_verb("a") && !is_verb("A.b") && !is_verb("a.b.c.d.e.f.g"));
        assert!(is_alias("refund") && is_alias("a.b") && !is_alias("") && !is_alias("1a"));
        assert!(is_id_role("id.user") && is_id_role("id.a.b.c.d") && !is_id_role("id") && !is_id_role("id.a.b.c.d.e") && !is_id_role("id.A"));
        assert!(is_custom_role("x.ns.name") && !is_custom_role("x.name") && is_custom_role("x.a.b.c.d") && !is_custom_role("x.a.b.c.d.e"));
        assert!(is_id_format("id:user") && is_id_format("id:a.b") && !is_id_format("id:") && !is_id_format("id.user"));
        assert!(
            is_taint_context("session_taint_max:low")
                && !is_taint_context("session_taint_max:")
                && !is_taint_context("session_taint_max:Low")
                && !is_taint_context("session_taint_max:abcdefghijklmnopq")
        );
        assert!(is_param_name("a") && is_param_name("a.b.c") && !is_param_name("a.b.c.d") && !is_param_name("a-b") && !is_param_name(""));
        assert!(is_trait_id("pca.money_moving") && !is_trait_id("pca") && !is_trait_id("pca.1x") && !is_trait_id("pca.a.b"));
        assert!(is_resource_type("invoice") && is_resource_type("a.b.c.d.e") && !is_resource_type("a.b.c.d.e.f") && !is_resource_type("a."));
        assert!(is_ns("acme") && !is_ns("Acme") && !is_ns(&"a".repeat(33)) && is_ns(&"a".repeat(32)));
    }

    #[test]
    fn tables_and_floors() {
        assert_eq!(core_trait_ids().len(), 22);
        assert_eq!(core_trait_ids()[0], "pca.money_moving");
        assert_eq!(core_trait_defs().len(), 22);
        assert_eq!(sensitivity_floor(Some("money.amount"), &[]), "critical");
        assert_eq!(sensitivity_floor(None, &["pii", "secret"]), "critical");
        assert_eq!(sensitivity_floor(Some("nope"), &["nope"]), "free");
        assert_eq!(effective_param_sensitivity(Some("person.name"), &[], Some("free")), "material");
        assert_eq!(effective_param_sensitivity(None, &[], Some("critical")), "critical");
        assert_eq!(join_all(&[]).risk, Profile::bottom().risk);
        assert_eq!((decision_rank("deny"), decision_rank("allow"), decision_rank("x")), (Some(0), Some(2), None));
        assert!(id_class_chars("uuid").is_some() && id_class_chars("x").is_none());
        assert!(builtin_release_ctx().is_none() && builtin_review_opts().is_none());
        assert_eq!(RULE22_ENGINE.decide(&json!({}), "a.b", &json!({}), &json!([])), "deny");
    }
}
