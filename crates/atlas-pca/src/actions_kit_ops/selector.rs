//! Trait selectors and the signed human confirmation (selector.ts + confirmation.ts of the reference).

use super::{isi, js_opt, negzero, sort_uniq16, u16cmp};
use crate::actions::{reviewer_pins_error, traits_digest, Registry};
use crate::agent::KeyPair;
use crate::{b64_encode, canonicalize_strict, hash_canonical_strict, verify_b64u};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const REVIEW_DOMAIN: &str = "atlas-pca/action-review/v2";
pub const VERB_FACTS_DOMAIN: &str = "atlas-pca/action-verb-facts/v1";

type Closure = BTreeSet<String>;

fn ids_of(s: &Value) -> Vec<&str> {
    s.get("ids").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

/// Does the selector match an action whose trait closure is `cl`? An unknown selector kind matches nothing.
pub fn selector_matches(s: &Value, cl: &Closure) -> bool {
    match s.get("k").and_then(Value::as_str) {
        Some("trait") => s.get("id").and_then(Value::as_str).is_some_and(|i| cl.contains(i)),
        Some("all_of") => ids_of(s).iter().all(|i| cl.contains(*i)),
        Some("any_of") => ids_of(s).iter().any(|i| cl.contains(*i)),
        Some("not") => !s.get("s").is_some_and(|x| selector_matches(x, cl)),
        Some("and") => s.get("a").is_some_and(|x| selector_matches(x, cl)) && s.get("b").is_some_and(|x| selector_matches(x, cl)),
        _ => false,
    }
}

/// Unconfirmed = maximally dangerous: every prohibit selector matches it, no allow selector ever does.
pub fn selector_matches_for(s: &Value, mode: &str, cl: &Closure, confirmed: bool) -> bool {
    if !confirmed {
        return mode == "prohibit";
    }
    selector_matches(s, cl)
}

pub fn selector_has_not(s: &Value) -> bool {
    match s.get("k").and_then(Value::as_str) {
        Some("not") => true,
        Some("and") => s.get("a").is_some_and(selector_has_not) || s.get("b").is_some_and(selector_has_not),
        _ => false,
    }
}

fn any_of_in(s: &Value) -> bool {
    match s.get("k").and_then(Value::as_str) {
        Some("any_of") => true,
        Some("and") => s.get("a").is_some_and(any_of_in) || s.get("b").is_some_and(any_of_in),
        _ => false,
    }
}

/// T7 typing rule for an ALLOW selector. `None` = allowed.
pub fn allow_selector_error(s: &Value, pinned: bool) -> Option<String> {
    if selector_has_not(s) {
        return Some("an allow selector must not use negation: the absence of a trait is never a safety claim".into());
    }
    if !pinned && any_of_in(s) {
        return Some("any_of in an allow selector requires the grant to be pinned to a pack digest".into());
    }
    None
}

/// `deny` / `escalate` / `allow` for one action of a trait policy `{pinned, allow, prohibit, on_new_action?}`.
pub fn policy_decision(p: &Value, verb: &str, cl: &Closure, confirmed: bool) -> &'static str {
    let list = |k: &str| p.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    if list("prohibit").iter().any(|s| selector_matches_for(s, "prohibit", cl, confirmed)) {
        return "deny";
    }
    if !list("pinned").iter().any(|v| v.as_str() == Some(verb)) {
        return if p.get("on_new_action").and_then(Value::as_str) == Some("escalate") { "escalate" } else { "deny" };
    }
    if list("allow").iter().any(|s| selector_matches_for(s, "allow", cl, confirmed)) {
        "allow"
    } else {
        "deny"
    }
}

// ---- confirmation ---------------------------------------------------------------------------------------------------------

/// True iff a dismissal reason is nothing but white space and the C0 separators U+001C..U+001F.
pub fn blank_reason(s: &str) -> bool {
    s.chars().all(|c| crate::action_schema::is_js_ws(c) || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `factsDigest(verb)`: the verb minus `traits`, `floors`, `confirmation` and `def`. `None` when out of the strict profile.
pub fn facts_digest(v: &Value) -> Option<String> {
    let mut o = v.as_object()?.clone();
    for k in ["traits", "floors", "confirmation", "def"] {
        o.remove(k);
    }
    hash_canonical_strict(&json!({"d": VERB_FACTS_DOMAIN, "verb": o}))
}

fn str_list(v: Option<&Value>) -> Result<Vec<String>, String> {
    v.and_then(Value::as_array)
        .ok_or("final_traits must be a list")?
        .iter()
        .map(|x| x.as_str().map(String::from).ok_or_else(|| "a trait must be a string".to_string()))
        .collect()
}

/// `REVIEW_DOMAIN \0 strictCanonical({def_digest, traits_digest, facts_digest, final_traits (sorted), dismissed (by trait), reviewer_kid, ts})`.
pub fn review_message(b: &Value) -> Result<Vec<u8>, String> {
    let fin = sort_uniq16(str_list(b.get("final_traits"))?);
    let mut dm: Vec<(String, Value)> = Vec::new();
    for d in b.get("dismissed").and_then(Value::as_array).ok_or("dismissed must be a list")? {
        let t = d.get("trait").and_then(Value::as_str).ok_or("dismissed trait must be a string")?.to_string();
        dm.push((t.clone(), json!({"trait": t, "reason": d.get("reason").cloned().ok_or("a dismissal needs a reason")?})));
    }
    dm.sort_by(|x, y| u16cmp(&x.0, &y.0));
    let g = |k: &str| b.get(k).cloned().ok_or_else(|| format!("missing {k}"));
    let body = json!({
        "def_digest": g("def_digest")?, "traits_digest": g("traits_digest")?, "facts_digest": g("facts_digest")?, "final_traits": fin,
        "dismissed": dm.into_iter().map(|x| x.1).collect::<Vec<_>>(), "reviewer_kid": g("reviewer_kid")?, "ts": g("ts")?,
    });
    let mut m = format!("{REVIEW_DOMAIN}\0").into_bytes();
    m.extend_from_slice(canonicalize_strict(&body)?.as_bytes());
    Ok(m)
}

/// The signed ReviewRef for `b` (final_traits sorted and distinct, dismissed sorted by trait), signed with an Ed25519 seed.
pub fn sign_review(b: &Value, secret: &[u8]) -> Result<Value, String> {
    let seed: [u8; 32] = secret.try_into().map_err(|_| "the reviewer key must be a 32-byte Ed25519 secret".to_string())?;
    let mut norm: Map<String, Value> = b.as_object().ok_or("the review body must be an object")?.clone();
    let fin = sort_uniq16(str_list(b.get("final_traits"))?);
    norm.insert("final_traits".into(), super::jstrs(&fin));
    let mut dm: Vec<Value> = b.get("dismissed").and_then(Value::as_array).ok_or("dismissed must be a list")?.clone();
    dm.sort_by(|x, y| u16cmp(x.get("trait").and_then(Value::as_str).unwrap_or(""), y.get("trait").and_then(Value::as_str).unwrap_or("")));
    norm.insert("dismissed".into(), Value::Array(dm));
    let norm = Value::Object(norm);
    let sig = KeyPair::from_seed(&seed).sign(&review_message(&norm)?);
    let mut out = norm.as_object().unwrap().clone();
    out.insert("sig".into(), Value::String(b64_encode(&sig)));
    Ok(Value::Object(out))
}

/// `verbConfirmationError`: `None` iff this schema verb carries a valid human confirmation; else the reason. `pins == None` is
/// "no reviewer keys are pinned". Never panics.
pub fn verb_confirmation_error(v: &Value, reg: &Registry, pins: Option<&Value>) -> Option<String> {
    let Some(pins) = pins else { return Some("no reviewer keys are pinned".into()) };
    if let Some(pe) = reviewer_pins_error(pins) {
        return Some(format!("bad pins: {pe}"));
    }
    let a = match v.get("confirmation") {
        None => return Some("no confirmation".into()),
        Some(a) => a,
    };
    if a.is_array() {
        return Some("the confirmation is unsigned".into()); // typeof [] is 'object': it has no sig
    }
    let Some(a) = a.as_object() else { return Some("confirmation is not an object".into()) };
    if !a.get("sig").is_some_and(Value::is_string) {
        return Some("the confirmation is unsigned".into());
    }
    let def = v.get("def").and_then(Value::as_str);
    if def.is_none() || a.get("def_digest").and_then(Value::as_str) != def {
        return Some("the confirmation covers a different def digest".into());
    }
    let td = a.get("traits_digest").and_then(Value::as_str);
    let ok_reg = td.is_some_and(|d| {
        d == traits_digest(reg) || pins.get("traits_digests").and_then(Value::as_array).is_some_and(|x| x.iter().any(|y| y.as_str() == Some(d)))
    });
    if !ok_reg {
        return Some("the confirmation was made against a different trait registry".into());
    }
    let fd = a.get("facts_digest").and_then(Value::as_str);
    let Some(fd) = fd else { return Some("the verb facts differ from the facts the reviewer confirmed".into()) };
    match facts_digest(v) {
        None => return Some("malformed confirmation: canonicalize failed".into()),
        Some(x) if x != fd => return Some("the verb facts differ from the facts the reviewer confirmed".into()),
        _ => {}
    }
    let ts = a.get("ts").filter(|t| isi(t) && !negzero(t));
    let (Some(fin), Some(dis), Some(ts), Some(kid)) =
        (a.get("final_traits").and_then(Value::as_array), a.get("dismissed").and_then(Value::as_array), ts, a.get("reviewer_kid").and_then(Value::as_str))
    else {
        return Some("malformed confirmation".into());
    };
    let carried: Vec<&str> = v.get("traits").and_then(Value::as_array).map(|t| t.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    if fin.iter().any(|t| t.as_str().map_or(true, |t| !carried.contains(&t))) {
        return Some("the verb does not carry every trait the reviewer signed".into());
    }
    let finset: BTreeSet<&str> = fin.iter().filter_map(Value::as_str).collect();
    let bad_dismissal = dis.iter().any(|d| match (d.get("trait").and_then(Value::as_str), d.get("reason").and_then(Value::as_str)) {
        (Some(t), Some(r)) => finset.contains(t) || blank_reason(r),
        _ => true,
    });
    if bad_dismissal {
        return Some("a dismissed trait is also final, or has no reason".into());
    }
    let key = pins.get("keys").and_then(Value::as_array).and_then(|ks| ks.iter().find(|k| k.get("kid").and_then(Value::as_str) == Some(kid)));
    let Some(key) = key else { return Some(format!("no pinned key '{kid}'")) };
    if !super::strs_of(key.get("roles")).iter().any(|r| r == "reviewer") {
        return Some(format!("key '{}' does not hold the reviewer role", js_opt(key.get("kid"))));
    }
    let tsf = ts.as_f64().unwrap_or(0.0);
    let before = key.get("not_before").and_then(Value::as_f64).is_some_and(|b| tsf < b);
    let after = key.get("not_after").and_then(Value::as_f64).is_some_and(|e| tsf > e);
    if before || after {
        return Some("the confirmation time is outside the key validity".into());
    }
    let mut body = a.clone();
    let sig = body.remove("sig").and_then(|s| s.as_str().map(String::from)).unwrap_or_default();
    match review_message(&Value::Object(body)) {
        Err(e) => Some(format!("malformed confirmation: {e}")),
        Ok(m) => {
            if verify_b64u(key.get("pk").and_then(Value::as_str).unwrap_or(""), &m, &sig) {
                None
            } else {
                Some("the confirmation signature is invalid".into())
            }
        }
    }
}
