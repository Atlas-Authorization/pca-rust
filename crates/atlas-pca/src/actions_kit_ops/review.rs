//! The confirmation flow and signed review attestations (import/review.ts): the verdict with its reasons, review status, the
//! review queue and view, and the producer side (`confirm_def`). A def WITHOUT a valid attestation has the top of the registry as
//! its effective traits; one counts only when a key pinned with the reviewer role signed this exact def digest.

use super::deps;
use super::effective::{effective_with, implied_traits};
use super::selector::{blank_reason, facts_digest, review_message, sign_review};
use super::{isi, js_opt, js_trim, jstrs, kerr, negzero, sort_uniq16, strs_of, u16cmp, utf16_len};
use crate::actions::{closure, def_digest, normalize, reviewer_pins_error, traits_digest, validate_def, ActionKitError, Registry};
use crate::agent::KeyPair;
use crate::verify_b64u;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

const SUSPECT: [&str; 5] = ["pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication"];
const NEXT: [&str; 8] = [
    "pca.credential_access",
    "pca.data_export",
    "pca.regulated_data",
    "pca.public_exposure",
    "pca.infra_mutation",
    "pca.legal_binding",
    "pca.impersonation",
    "pca.persistence",
];

fn fail(reason: &str, detail: impl Into<String>) -> Value {
    json!({"ok": false, "reason": reason, "detail": detail.into()})
}

/// `{ok: true, kid}` iff the confirmation is valid, else `{ok: false, reason, detail}`. Never panics.
pub fn verify_attestation_verdict(d: &Value, reg: &Registry, pins: &Value) -> Value {
    if let Some(pe) = reviewer_pins_error(pins) {
        return fail("bad_pins", pe);
    }
    let review = d.get("review").filter(|r| r.is_object());
    if review.and_then(|r| r.get("state")).and_then(Value::as_str) != Some("confirmed") {
        return fail("not_confirmed", "review.state is not confirmed");
    }
    let review = review.unwrap();
    let a = match review.get("attestation") {
        None => return fail("no_attestation", "a confirmed def carries an attestation"),
        Some(a) => a,
    };
    let empty = Map::new();
    let a = a.as_object().unwrap_or(&empty); // a scalar or array has no members: unsigned
    let Some(sig) = a.get("sig").and_then(Value::as_str) else { return fail("no_signature", "the attestation is unsigned") };
    if !a.get("facts_digest").is_some_and(Value::is_string) {
        return fail("malformed", "the attestation facts_digest must be a string");
    }
    let ft = a.get("final_traits").and_then(Value::as_array).filter(|t| t.iter().all(Value::is_string));
    let dis = a
        .get("dismissed")
        .and_then(Value::as_array)
        .filter(|x| x.iter().all(|y| y.get("trait").is_some_and(Value::is_string) && y.get("reason").is_some_and(Value::is_string)));
    let ts_ok = a.get("ts").is_some_and(|t| isi(t) && !negzero(t));
    let (Some(ft), Some(dis), true, Some(kid)) = (ft, dis, ts_ok, a.get("reviewer_kid").and_then(Value::as_str)) else {
        return fail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed");
    };
    if a.get("def_digest").and_then(Value::as_str) != def_digest(d).as_deref() {
        return fail("digest_mismatch", "the def changed after it was reviewed");
    }
    let td = a.get("traits_digest").and_then(Value::as_str);
    let accepted = td.is_some_and(|x| x == traits_digest(reg) || strs_of(pins.get("traits_digests")).iter().any(|y| y == x));
    if !accepted {
        return fail("traits_digest_mismatch", "the trait registry changed since the review");
    }
    let fin_s: Vec<String> = ft.iter().filter_map(|x| x.as_str().map(String::from)).collect();
    if sort_uniq16(fin_s.clone()) != sort_uniq16(strs_of(d.get("traits"))) {
        return fail("final_traits_mismatch", "the attested final traits are not the def's declared traits");
    }
    let fin: BTreeSet<&str> = fin_s.iter().map(String::as_str).collect();
    if dis.iter().any(|x| fin.contains(x["trait"].as_str().unwrap_or("")) || blank_reason(x["reason"].as_str().unwrap_or(""))) {
        return fail("dismissed_conflict", "a dismissed trait is also final, or has no reason");
    }
    let key = pins["keys"].as_array().and_then(|ks| ks.iter().find(|k| k["kid"].as_str() == Some(kid)));
    let Some(key) = key else { return fail("unknown_reviewer", format!("no pinned key '{kid}'")) };
    if !strs_of(key.get("roles")).iter().any(|r| r == "reviewer") {
        return fail("not_a_reviewer", format!("key '{}' does not hold the reviewer role", js_opt(key.get("kid"))));
    }
    let ts = a["ts"].as_f64().unwrap_or(0.0);
    if key.get("not_before").and_then(Value::as_f64).is_some_and(|b| ts < b) || key.get("not_after").and_then(Value::as_f64).is_some_and(|e| ts > e) {
        return fail("outside_validity", "the attestation time is outside the key validity");
    }
    let mut body = a.clone();
    body.remove("sig");
    match review_message(&Value::Object(body)) {
        Ok(m) if verify_b64u(key["pk"].as_str().unwrap_or(""), &m, sig) => json!({"ok": true, "kid": key["kid"]}),
        Ok(_) => fail("bad_signature", "the attestation signature is invalid"),
        Err(e) => fail("malformed", e),
    }
}

/// The callback the algebra takes: a confirmed def counts only if the attestation verdict is ok.
pub fn attestation_verifier<'a>(reg: &'a Registry, pins: &'a Value) -> impl Fn(&Value) -> bool + 'a {
    move |d| verify_attestation_verdict(d, reg, pins)["ok"] == Value::Bool(true)
}

/// The state that counts: a `confirmed` def with an invalid attestation is `stale`.
pub fn review_status(d: &Value, reg: &Registry, pins: &Value) -> String {
    let st = d["review"]["state"].as_str().unwrap_or("").to_string();
    if st != "confirmed" {
        return st;
    }
    if verify_attestation_verdict(d, reg, pins)["ok"] == Value::Bool(true) {
        "confirmed".into()
    } else {
        "stale".into()
    }
}

/// Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped).
pub fn revert_stale(d: &Value, reg: &Registry, pins: &Value) -> Value {
    if review_status(d, reg, pins) != "stale" {
        return d.clone();
    }
    let mut r = d["review"].as_object().cloned().unwrap_or_default();
    r.remove("attestation");
    r.insert("state".into(), json!("unreviewed"));
    let mut out = d.as_object().cloned().unwrap_or_default();
    out.insert("review".into(), Value::Object(r));
    Value::Object(out)
}

/// 0 = a core suspect trait, 1 = other risky, 2 = the rest.
pub fn review_priority(d: &Value, reg: &Registry) -> Result<i64, ActionKitError> {
    let cl = effective_with(d, reg, None)?.hint.closure;
    Ok(if SUSPECT.iter().any(|t| cl.iter().any(|c| c == t)) {
        0
    } else if NEXT.iter().any(|t| cl.iter().any(|c| c == t)) {
        1
    } else {
        2
    })
}

/// Defs in review order: suspect traits first, then by risk (highest first), then by verb.
pub fn review_queue_order(defs: &[Value], reg: &Registry) -> Result<Vec<Value>, ActionKitError> {
    let mut rows: Vec<(i64, i64, &Value)> = Vec::new();
    for d in defs {
        rows.push((review_priority(d, reg)?, effective_with(d, reg, None)?.hint.eff.risk, d));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then_with(|| u16cmp(a.2["verb"].as_str().unwrap_or(""), b.2["verb"].as_str().unwrap_or(""))));
    Ok(rows.into_iter().map(|r| r.2.clone()).collect())
}

fn sj(o: &Value, k: &str) -> String {
    o.get(k).map_or_else(|| "undefined".to_string(), crate::js_stringify)
}

/// What the reviewer is shown: the def's facts, the traits it would carry once signed, the policy card and what changed.
pub fn prepare_review(d: &Value, reg: &Registry, previous: Option<&Value>) -> Result<Value, String> {
    let eff = effective_with(d, reg, None).map_err(super::msg)?;
    let sb = d["review"].get("suggested_by").cloned().unwrap_or_else(|| json!({}));
    let mut changes: Vec<String> = Vec::new();
    if let Some(p) = previous {
        let skip = ["review", "examples", "source", "since"];
        let (a, b) = (p.as_object().cloned().unwrap_or_default(), d.as_object().cloned().unwrap_or_default());
        let keys: BTreeSet<&String> = a.keys().chain(b.keys()).filter(|k| !skip.contains(&k.as_str())).collect();
        changes = keys.into_iter().filter(|k| sj(p, k) != sj(d, k)).cloned().collect();
        changes.sort_by(|x, y| u16cmp(x, y));
    }
    Ok(json!({
        "verb": d["verb"], "def_digest": def_digest(d), "state": d["review"]["state"], "declared_traits": sort_uniq16(strs_of(d.get("traits"))),
        "implied_traits": implied_traits(&normalize(d))?,
        "suggested": sb.get("added").filter(|a| !a.is_null()).cloned().unwrap_or_else(|| json!({"traits": [], "roles": {}, "tags": {}})),
        "effective": {"confirmed": eff.confirmed, "traits": eff.main.traits, "closure": eff.main.closure, "floor": eff.main.floor.to_value(), "eff": eff.main.eff.to_value(),
                      "decl": eff.decl.to_value(), "hint": {"traits": eff.hint.traits, "closure": eff.hint.closure, "floor": eff.hint.floor.to_value(), "eff": eff.hint.eff.to_value()},
                      "clamps": eff.clamps.iter().map(|c| json!({"field": c.field, "declared": c.declared, "floor": c.floor})).collect::<Vec<_>>()},
        "card": deps::card_of_shown(d, reg)?, "changes": changes, "priority": review_priority(d, reg).map_err(super::msg)?,
    }))
}

fn bad_confirm(m: impl Into<String>) -> ActionKitError {
    kerr("bad_confirm", m)
}

/// Review one def: validate the decision, write the final traits, sign an attestation over the resulting digest, return the confirmed def.
/// `o`: `{finalTraits, dismissed?, ts, reviewer: {kid}, pins?}`; `reviewer_secret` is the 32-byte Ed25519 seed. Errors carry the reference
/// codes `bad_confirm`, `undismissed_suggestion`, `not_reviewer` in their message prefix.
pub fn confirm_def(d: &Value, reg: &Registry, o: &Value, reviewer_secret: &[u8]) -> Result<Value, ActionKitError> {
    let ts = o.get("ts");
    if !ts.is_some_and(|t| isi(t) && !negzero(t) && t.as_f64().unwrap_or(-1.0) >= 0.0) {
        return Err(bad_confirm("ts must be a non-negative integer"));
    }
    let want = strs_of(o.get("finalTraits"));
    let final_t = sort_uniq16(want.clone());
    if final_t.len() != want.len() {
        return Err(bad_confirm("final traits must be distinct"));
    }
    for t in &final_t {
        if !reg.traits.contains_key(t) {
            return Err(bad_confirm(format!("unknown trait '{t}'")));
        }
        if t == "pca.unreviewed" {
            return Err(bad_confirm("'pca.unreviewed' is the review marker, not a final trait"));
        }
    }
    let dismissed: Vec<Value> =
        o.get("dismissed").and_then(Value::as_array).cloned().unwrap_or_default().iter().map(|x| json!({"trait": x["trait"], "reason": x["reason"]})).collect();
    let mut dset: BTreeSet<String> = BTreeSet::new();
    for x in &dismissed {
        let t = x["trait"].as_str().unwrap_or("").to_string();
        let reason = x["reason"].as_str();
        if reason.map_or(true, |r| js_trim(r).is_empty() || utf16_len(r) > 256) {
            return Err(bad_confirm(format!("dismissed trait '{t}' needs a reason (1..256 characters)")));
        }
        if !dset.insert(t.clone()) {
            return Err(bad_confirm(format!("trait '{t}' is dismissed twice")));
        }
        if final_t.contains(&t) {
            return Err(bad_confirm(format!("trait '{t}' is both final and dismissed")));
        }
    }
    let sb = d["review"].get("suggested_by").cloned().unwrap_or_else(|| json!({}));
    let mut shown_src = strs_of(d.get("traits"));
    shown_src.extend(strs_of(sb.get("added").and_then(|a| a.get("traits"))));
    let shown = sort_uniq16(shown_src);
    let mut cover_src = final_t.clone();
    cover_src.extend(implied_traits(&normalize(d)).map_err(|e| bad_confirm(e))?);
    let covered: BTreeSet<String> = closure(reg, &sort_uniq16(cover_src))?.into_iter().collect();
    for t in &shown {
        if final_t.contains(t) || covered.contains(t) {
            continue;
        }
        if !dset.contains(t) {
            return Err(kerr("undismissed_suggestion", format!("trait '{t}' was suggested and is not in the final set: record it as dismissed with a reason")));
        }
    }
    for t in &dset {
        if !shown.contains(t) {
            return Err(bad_confirm(format!("trait '{t}' was never suggested; nothing to dismiss")));
        }
    }
    let kid = o["reviewer"]["kid"].as_str().unwrap_or("");
    let seed: [u8; 32] = reviewer_secret.try_into().map_err(|_| bad_confirm("the reviewer key must be a 32-byte Ed25519 secret"))?;
    if let Some(pins) = o.get("pins").filter(|p| !p.is_null()) {
        if let Some(pe) = reviewer_pins_error(pins) {
            return Err(bad_confirm(pe));
        }
        let key = pins["keys"].as_array().and_then(|ks| ks.iter().find(|k| k["kid"].as_str() == Some(kid)));
        match key {
            Some(k) if strs_of(k.get("roles")).iter().any(|r| r == "reviewer") => {
                if k["pk"].as_str() != Some(KeyPair::from_seed(&seed).public.as_str()) {
                    return Err(kerr("not_reviewer", format!("the secret does not belong to the pinned key '{kid}'")));
                }
            }
            _ => return Err(kerr("not_reviewer", format!("key '{kid}' is not pinned with the reviewer role"))),
        }
    }
    let mut body = d.as_object().cloned().unwrap_or_default();
    if final_t.is_empty() {
        body.remove("traits");
    } else {
        body.insert("traits".into(), jstrs(&final_t));
    }
    let body = Value::Object(body);
    let digest = def_digest(&body).ok_or_else(|| bad_confirm("the def is out of the strict profile"))?;
    let facts =
        facts_digest(&deps::to_schema_verb(&body, reg).map_err(bad_confirm)?["verb"]).ok_or_else(|| bad_confirm("the verb is out of the strict profile"))?;
    let att = sign_review(
        &json!({"def_digest": digest, "traits_digest": traits_digest(reg), "facts_digest": facts, "final_traits": final_t, "dismissed": dismissed, "reviewer_kid": kid, "ts": ts}),
        &seed,
    )
    .map_err(bad_confirm)?;
    let mut rv = d["review"].as_object().cloned().unwrap_or_default();
    rv.insert("state".into(), json!("confirmed"));
    rv.insert("attestation".into(), att);
    let mut out = body.as_object().cloned().unwrap_or_default();
    out.insert("review".into(), Value::Object(rv));
    let out = Value::Object(out);
    if let Some(bad) = validate_def(&out) {
        return Err(bad_confirm(format!("the confirmed def is invalid: {bad}")));
    }
    Ok(out)
}

/// A `Verifier` over the pinned reviewer keys (`None` pins: nothing is confirmed).
pub fn review_opts_of<'a>(pins: Option<&'a Value>, reg: &'a Registry) -> Option<Box<dyn Fn(&Value) -> bool + 'a>> {
    pins.map(|p| Box::new(attestation_verifier(reg, p)) as Box<dyn Fn(&Value) -> bool + 'a>)
}

/// Release step: confirm (sign) every def of `defs` (the built-in defs when absent) with the release reviewer key; the final traits are the
/// def's own, sorted and distinct. `reviewer_secret` is the caller's 32-byte seed and is never stored.
pub fn sign_builtins(kid: &str, reviewer_secret: &[u8], ts: i64, registry: Option<&Registry>, defs: Option<&[Value]>) -> Result<Vec<Value>, ActionKitError> {
    let core = crate::actions::core_registry();
    let reg = registry.unwrap_or(&core);
    let own;
    let defs: &[Value] = match defs {
        Some(d) => d,
        None => {
            own = crate::actions_kit::data::builtin_defs();
            &own
        }
    };
    defs.iter()
        .map(|d| {
            let o = json!({"finalTraits": sort_uniq16(strs_of(d.get("traits"))), "ts": ts, "reviewer": {"kid": kid}});
            confirm_def(d, reg, &o, reviewer_secret)
        })
        .collect()
}
