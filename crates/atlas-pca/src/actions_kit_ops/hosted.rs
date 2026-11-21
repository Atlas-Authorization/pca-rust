//! The hosted action registry of one instance: the publish gate and the verifier's view of the active versions (hosted.ts). Pure:
//! storage, keys and time are the caller's. Fail closed everywhere: an action the view does not know, that no pinned reviewer key
//! confirmed, or that is deprecated gets the top of the trait registry, no provenance facts, is irreversible and never undoable.

use super::effective::{effective_with, is_confirmed};
use super::render::provenance_info_of;
use super::review::attestation_verifier;
use super::rules::{compile_business_rules, diff_business_rules, lint_business_rules, rules_review_error};
use super::undo::undo_engine;
use super::{js_str, nonneg, sort_u16, sort_uniq16, strs_of, u16cmp, Verifier};
use crate::actions::{
    core_registry, def_digest, extend_registry, floor_decision, floor_of, join, leq, pack_root, top_traits, traits_digest, validate_def, ActionKitError,
    GrantFacts, Profile, Registry, CAVEAT_KINDS,
};
use crate::actions_registry::compare_versions;
use crate::authorize::read_envelope;
use crate::{canonicalize_strict, hash_canonical_strict, verify_b64u};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const RULES_DOC_KIND: &str = "pca-action-rules";
const HOSTED_VERSION_DOMAIN: &str = "atlas-pca/hosted-action-version/v1";
const PACK_SIGN_DOMAIN: &str = "atlas-pca/action-pack/v1\0";
const MAX_UNSHARDED_DEFS: usize = 4096;
const EFFECTIVE_DIMS: [&str; 3] = ["confirmation", "effective.traits", "effective.profile"];

/// The trait registry of a version: core plus its custom traits. An error for custom traits that do not extend their `implies`.
pub fn registry_of_traits(traits: &[Value]) -> Result<Registry, ActionKitError> {
    let core = core_registry();
    if traits.is_empty() {
        Ok(core)
    } else {
        extend_registry(&core, traits)
    }
}

/// Run `f` with the confirmation verifier of an instance: a signature by a pinned reviewer key (no pins: nothing is confirmed).
pub fn with_verifier<R>(pins: Option<&Value>, reg: &Registry, f: impl FnOnce(Verifier) -> R) -> R {
    match pins.filter(|p| !p.is_null()) {
        None => f(None),
        Some(p) => {
            let c = attestation_verifier(reg, p);
            f(Some(&c))
        }
    }
}

/// `None` iff `x` is a rules document for `ns` whose every verb is in `defs` and whose rules lint without errors.
pub fn rules_doc_error(x: &Value, ns: &str, defs: &[Value]) -> Option<String> {
    let Some(xo) = x.as_object() else { return Some("rules must be a pca-action-rules document".into()) };
    for k in xo.keys() {
        if !["v", "kind", "ns", "rules", "reviews"].contains(&k.as_str()) {
            return Some(format!("rules: unknown member '{k}'"));
        }
    }
    if !xo.get("v").is_some_and(|v| v.as_f64() == Some(1.0)) || xo.get("kind").and_then(Value::as_str) != Some(RULES_DOC_KIND) {
        return Some(format!("rules: not a {RULES_DOC_KIND} v1 document"));
    }
    if xo.get("ns").and_then(Value::as_str) != Some(ns) {
        return Some(format!("rules: ns '{}' is not the pack's '{ns}'", xo.get("ns").map_or("undefined".to_string(), js_str)));
    }
    let Some(rules) = xo.get("rules").and_then(Value::as_object) else { return Some("rules.rules must map verbs to rules blocks".into()) };
    if xo.get("reviews").is_some_and(|r| !r.is_object()) {
        return Some("rules.reviews must map verbs to rules reviews".into());
    }
    let by_verb: BTreeMap<&str, &Value> = defs.iter().filter_map(|d| d["verb"].as_str().map(|v| (v, d))).collect();
    for (verb, block) in rules {
        let Some(d) = by_verb.get(verb.as_str()) else { return Some(format!("rules: '{verb}' is not an action of the pack")) };
        let errs: Vec<String> =
            lint_business_rules(d, block).iter().filter(|f| f["severity"] == "error").map(|f| f["message"].as_str().unwrap_or("").to_string()).collect();
        if !errs.is_empty() {
            return Some(format!("rules for '{verb}': {}", errs.join("; ")));
        }
    }
    for verb in xo.get("reviews").and_then(Value::as_object).into_iter().flat_map(|m| m.keys()) {
        if !by_verb.contains_key(verb.as_str()) {
            return Some(format!("rules.reviews: '{verb}' is not an action of the pack"));
        }
    }
    None
}

/// Digest of a hosted version `{pack, rules, traits, deprecated}`.
pub fn hosted_version_digest(v: &Value) -> Result<String, String> {
    let mut dep = strs_of(v.get("deprecated"));
    sort_u16(&mut dep);
    hash_canonical_strict(&json!({"d": HOSTED_VERSION_DOMAIN, "pack": v["pack"], "rules": v["rules"], "traits": v["traits"], "deprecated": dep}))
        .ok_or_else(|| "the version is not strictly canonical".to_string())
}

fn fail(code: &str, reason: impl Into<String>, verbs: Option<Vec<String>>) -> Value {
    let mut o = Map::new();
    o.insert("ok".into(), json!(false));
    o.insert("code".into(), json!(code));
    o.insert("reason".into(), json!(reason.into()));
    if let Some(v) = verbs.filter(|v| !v.is_empty()) {
        o.insert("verbs".into(), json!(v));
    }
    Value::Object(o)
}

// ---- a signed pack of build.ts ------------------------------------------------------------------------------------------------

/// `None` when the pack is internally consistent: every def valid and unique, the Merkle root and digests recomputed.
pub fn pack_consistency_error(p: &Value, reg: &Registry) -> Option<String> {
    let Some(po) = p.as_object() else { return Some("the pack must be an object".into()) };
    if po.get("kind").and_then(Value::as_str) != Some("pca-action-pack")
        || po.get("v").and_then(Value::as_f64) != Some(1.0)
        || po.get("v").is_some_and(Value::is_boolean)
    {
        return Some("not a pca-action-pack v1".into());
    }
    let Some(defs) = po.get("defs").and_then(Value::as_array).filter(|d| d.len() <= MAX_UNSHARDED_DEFS) else {
        return Some("defs must be a list within the unsharded limit".into());
    };
    let mut seen = BTreeSet::new();
    for d in defs {
        if let Some(e) = validate_def(d) {
            return Some(format!("def {}: {e}", d.get("verb").and_then(Value::as_str).unwrap_or("?")));
        }
        if !seen.insert(d["verb"].as_str().unwrap_or("").to_string()) {
            return Some(format!("verb '{}' is defined twice", d["verb"].as_str().unwrap_or("")));
        }
    }
    let digests: Vec<String> = defs.iter().map(|d| def_digest(d).unwrap_or_default()).collect();
    match pack_root(&digests) {
        Ok(r) if po.get("root").and_then(Value::as_str) == Some(r.as_str()) => {}
        Ok(_) => return Some("the pack root does not match its defs".into()),
        Err(e) => return Some(format!("malformed pack: {}", e.message)),
    }
    if po.get("traits_digest").and_then(Value::as_str) != Some(traits_digest(reg).as_str()) {
        return Some("traits_digest does not match the trait registry".into());
    }
    None
}

/// Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never panics.
pub fn verify_signed_pack(pack: &Value, keys: &Value, reg: &Registry) -> Value {
    let no = |r: String| json!({"ok": false, "reason": r});
    if let Some(bad) = pack_consistency_error(pack, reg) {
        return no(bad);
    }
    let sig = pack.get("sig").and_then(Value::as_object);
    let Some(sig) = sig.filter(|s| {
        s.get("alg").and_then(Value::as_str) == Some("ed25519") && s.get("kid").is_some_and(Value::is_string) && s.get("value").is_some_and(Value::is_string)
    }) else {
        return no("missing or malformed signature".into());
    };
    let kid = sig["kid"].as_str().unwrap_or("");
    let Some(k) = keys.as_array().and_then(|ks| ks.iter().find(|x| x["kid"].as_str() == Some(kid))) else {
        return no(format!("no registry key with kid '{kid}'"));
    };
    if k.get("alg").and_then(Value::as_str) != Some("ed25519")
        || !k.get("pk").and_then(Value::as_str).is_some_and(|p| crate::decode_b64u_strict(p, Some(32)).is_some())
    {
        return no("the registry key entry is malformed".into());
    }
    let mut body = pack.as_object().cloned().unwrap_or_default();
    body.remove("sig");
    let Ok(canon) = canonicalize_strict(&Value::Object(body)) else { return no("pack verification error: not strictly canonical".into()) };
    let mut msg = PACK_SIGN_DOMAIN.as_bytes().to_vec();
    msg.extend_from_slice(canon.as_bytes());
    if verify_b64u(k["pk"].as_str().unwrap_or(""), &msg, sig["value"].as_str().unwrap_or("")) {
        json!({"ok": true})
    } else {
        no("pack signature invalid".into())
    }
}

// ---- the publish gate -----------------------------------------------------------------------------------------------------------

fn safe_confirmed(d: &Value, v: Verifier) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| is_confirmed(d, v))).unwrap_or(false)
}

/// `diff_defs`, but each side under its own registry and review (a trait registry change shows up in the effective dimensions).
fn diff_defs_across(o: &Value, n: &Value, o_reg: &Registry, n_reg: &Registry, same_reg: bool, o_rev: Verifier, n_rev: Verifier) -> Result<Value, String> {
    let base = super::deps::diff_defs(o, n, n_reg, n_rev)?;
    if same_reg {
        return Ok(base);
    }
    let eo = effective_with(o, o_reg, o_rev).map_err(super::msg)?.main.eff;
    let en = effective_with(n, n_reg, n_rev).map_err(super::msg)?.main.eff;
    // the reference's own relation: le(old, new) without le(new, old) is `narrow`, le(new, old) alone is `widen`
    let rel = if leq(&eo, &en) {
        if leq(&en, &eo) {
            return Ok(base);
        }
        "narrow"
    } else if leq(&en, &eo) {
        "widen"
    } else {
        "incomparable"
    };
    let bc = base["class"].as_str().unwrap_or("");
    let mut reasons: Vec<String> =
        base["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|r| !r.starts_with("effective.profile")).map(String::from).collect();
    reasons.push(format!("effective.profile: {rel}"));
    sort_u16(&mut reasons);
    let cls = if rel == "incomparable" || bc == "incomparable" || (rel == "widen" && bc == "narrow") || (rel == "narrow" && bc == "widen") {
        "incomparable"
    } else if rel == "widen" || bc == "widen" {
        "widen"
    } else {
        "narrow"
    };
    Ok(json!({"class": cls, "reasons": reasons}))
}

/// Decide whether a version may become the active one of its namespace and compute what it changes. `i`: `{current?, pack, rules?,
/// traits?, publisherKeys, pins?, pin?}`. Refused: bad_pack, bad_traits, bad_rules, ns_mismatch, bad_version / not_newer,
/// widen_unreviewed. Removed actions become deprecated.
pub fn publish_gate(i: &Value) -> Value {
    let mut thrown = None;
    let v = publish_gate_inner(i, &mut thrown);
    match thrown {
        // never publish on a comparison that could not be made
        Some(e) => fail("compare_failed", e, None),
        None => v,
    }
}

/// [`publish_gate`] as the reference runs it: a comparison that cannot be made (a trait the registry does not know) THROWS out of the
/// gate instead of publishing; `Err` carries that message.
pub fn publish_gate_checked(i: &Value) -> Result<Value, String> {
    let mut thrown = None;
    let v = publish_gate_inner(i, &mut thrown);
    thrown.map_or(Ok(v), Err)
}

fn publish_gate_inner(i: &Value, thrown: &mut Option<String>) -> Value {
    let mut traits: Vec<Value> = Vec::new();
    if let Some(t) = i.get("traits") {
        match t.as_array() {
            Some(a) => traits = a.clone(),
            None => return fail("bad_traits", "traits must be a list of trait definitions", None),
        }
    }
    let reg = match registry_of_traits(&traits) {
        Ok(r) => r,
        Err(e) => return fail("bad_traits", e.message, None),
    };
    let pack = i.get("pack").cloned().unwrap_or(Value::Null);
    let pv = verify_signed_pack(&pack, i.get("publisherKeys").unwrap_or(&Value::Null), &reg);
    if pv["ok"] != Value::Bool(true) {
        return fail("bad_pack", pv["reason"].as_str().unwrap_or(""), None);
    }
    let (ns, version) = (pack["ns"].as_str().unwrap_or(""), pack["version"].as_str().unwrap_or(""));
    if !regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").unwrap().is_match(version) {
        return fail("bad_version", format!("version '{version}' must be MAJOR.MINOR.PATCH"), None);
    }
    let cur = i.get("current").filter(|c| !c.is_null());
    if let Some(c) = cur {
        if c["ns"].as_str() != Some(ns) {
            return fail("ns_mismatch", format!("the active namespace is '{}', the pack is '{ns}'", js_str(&c["ns"])), None);
        }
        let pinned = i.get("pin").is_some_and(|p| p.as_bool() == Some(true));
        if !pinned {
            match compare_versions(version, c["version"].as_str().unwrap_or("")) {
                Ok(x) if x > 0 => {}
                Ok(_) => return fail("not_newer", format!("version {version} is not above the active {}", js_str(&c["version"])), None),
                Err(e) => return fail("bad_version", e, None),
            }
        }
    }
    let rules = i.get("rules").cloned().unwrap_or_else(|| json!({"v": 1, "kind": RULES_DOC_KIND, "ns": ns, "rules": {}}));
    let pdefs: Vec<Value> = pack["defs"].as_array().cloned().unwrap_or_default();
    if let Some(re) = rules_doc_error(&rules, ns, &pdefs) {
        return fail("bad_rules", re, None);
    }
    let pins = i.get("pins").filter(|p| !p.is_null());
    let prev_reg = match cur {
        Some(c) => registry_of_traits(c["traits"].as_array().map(Vec::as_slice).unwrap_or(&[])).unwrap_or_else(|_| reg.clone()),
        None => reg.clone(),
    };
    let same_reg = cur.is_none() || strs_of_digest(&prev_reg) == strs_of_digest(&reg);
    let mut changes: Vec<Value> = Vec::new();
    let (mut blocked, mut reasons): (Vec<String>, Vec<String>) = (vec![], vec![]);
    let old_defs: BTreeMap<String, Value> = cur
        .map(|c| c["pack"]["defs"].as_array().into_iter().flatten().map(|d| (d["verb"].as_str().unwrap_or("").to_string(), d.clone())).collect())
        .unwrap_or_default();
    let old_dep: BTreeSet<String> = cur.map(|c| strs_of(c.get("deprecated")).into_iter().collect()).unwrap_or_default();
    let new_verbs: BTreeSet<String> = pdefs.iter().filter_map(|d| d["verb"].as_str().map(String::from)).collect();
    for n in &pdefs {
        let verb = n["verb"].as_str().unwrap_or("").to_string();
        let o = old_defs.get(&verb);
        let new_rules = rules["rules"].get(&verb).filter(|r| !r.is_null());
        let confirmed = with_verifier(pins, &reg, |rv| safe_confirmed(n, rv));
        let mut change = Map::new();
        change.insert("verb".into(), json!(verb));
        let is_new = o.is_none() || old_dep.contains(&verb);
        if is_new {
            change.insert("class".into(), json!("added"));
            change.insert("reasons".into(), json!([]));
            if confirmed {
                change.insert("reviewed".into(), json!(true));
            }
        } else {
            let o = o.unwrap();
            let d = with_verifier(pins, &prev_reg, |orv| with_verifier(pins, &reg, |nrv| diff_defs_across(o, n, &prev_reg, &reg, same_reg, orv, nrv)));
            let d = d.unwrap_or_else(|e| {
                thrown.get_or_insert_with(|| e.clone());
                json!({"class": "incomparable", "reasons": [e]})
            });
            change.insert("class".into(), d["class"].clone());
            change.insert("reasons".into(), d["reasons"].clone());
            let rs: Vec<&str> = d["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            if rs.iter().any(|r| EFFECTIVE_DIMS.iter().any(|dim| r.starts_with(&format!("{dim}: widen")) || r.starts_with(&format!("{dim}: incomparable")))) {
                if confirmed {
                    change.insert("reviewed".into(), json!(true));
                } else {
                    blocked.push(verb.clone());
                    reasons.push(format!("{verb}: its effective authority widens without a valid confirmation of the new definition"));
                }
            }
        }
        let old_rules = if !is_new { cur.and_then(|c| c["rules"]["rules"].get(&verb)).filter(|r| !r.is_null()) } else { None };
        if old_rules.is_some() || new_rules.is_some() {
            let rd =
                diff_business_rules(n, old_rules, new_rules).unwrap_or_else(|e| json!({"class": "incomparable", "reasons": [format!("rules: {}", e.message)]}));
            if rd["class"] != "equal" {
                change.insert("rules".into(), rd.clone());
            }
            if matches!(rd["class"].as_str(), Some("widen") | Some("incomparable")) {
                let rv = rules.get("reviews").and_then(|r| r.get(&verb)).cloned().unwrap_or(Value::Null);
                let empty = json!({});
                let err = rules_review_error(&rv, n, new_rules.unwrap_or(&empty), pins);
                match err {
                    None => {
                        change.insert("reviewed".into(), json!(true));
                    }
                    Some(e) => {
                        blocked.push(verb.clone());
                        let rr: Vec<&str> = rd["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                        reasons.push(format!("{verb}: its business rules widen ({}) without a valid rules review: {e}", rr.join(", ")));
                    }
                }
            }
        }
        if change["class"] != "equal" || change.get("rules").is_some() {
            changes.push(Value::Object(change));
        }
    }
    let mut deprecated: BTreeSet<String> = old_dep.iter().filter(|v| !new_verbs.contains(*v)).cloned().collect();
    for v in old_defs.keys() {
        if new_verbs.contains(v) || old_dep.contains(v) {
            continue;
        }
        deprecated.insert(v.clone());
        changes.push(json!({"verb": v, "class": "deprecated", "reasons": ["removed from the namespace: treated as unknown"]}));
    }
    changes.sort_by(|a, b| u16cmp(a["verb"].as_str().unwrap_or(""), b["verb"].as_str().unwrap_or("")));
    if !blocked.is_empty() {
        let mut b = sort_uniq16(blocked);
        b.dedup();
        let mut out = fail("widen_unreviewed", reasons.join("\n"), Some(b));
        out["changes"] = Value::Array(changes);
        return out;
    }
    let mut dep: Vec<String> = deprecated.into_iter().collect();
    sort_u16(&mut dep);
    let body = json!({"pack": pack, "rules": rules, "traits": traits, "deprecated": dep});
    let Ok(digest) = hosted_version_digest(&body) else { return fail("bad_pack", "the version is not strictly canonical", None) };
    let mut ver = Map::new();
    ver.insert("ns".into(), json!(ns));
    ver.insert("version".into(), json!(version));
    ver.insert("digest".into(), json!(digest));
    ver.insert("prev".into(), cur.map_or(Value::Null, |c| c["digest"].clone()));
    for (k, v) in body.as_object().unwrap() {
        ver.insert(k.clone(), v.clone());
    }
    ver.insert("changes".into(), Value::Array(changes));
    json!({"ok": true, "version": ver})
}

fn strs_of_digest(r: &Registry) -> String {
    traits_digest(r)
}

// ---- the verifier's view ----------------------------------------------------------------------------------------------------------

/// Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers.
pub fn grant_facts_of(grant: &Value) -> Value {
    let env = read_envelope(grant).map(Value::Object);
    let a = env.as_ref().and_then(|e| e.get("actions")).filter(|a| a.is_object()).cloned().unwrap_or_else(|| json!({}));
    let tier = |v: Option<&Value>, d: i64| -> i64 {
        match v {
            Some(Value::Number(n)) if n.is_i64() || n.is_u64() => n.as_i64().filter(|x| (0..=3).contains(x)).unwrap_or(d),
            _ => d,
        }
    };
    let mut caveats: Vec<Value> = env
        .as_ref()
        .and_then(|e| e.get("caveats"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|c| if c.is_object() { c.get("type").cloned().unwrap_or(Value::Null) } else { Value::Null })
        .collect();
    if let Some(ac) = a.get("caveats").and_then(Value::as_array) {
        caveats.extend(ac.iter().cloned());
    }
    let caveats: Vec<&str> = caveats.iter().filter_map(Value::as_str).collect();
    json!({"caveats": caveats, "max_esc": tier(a.get("max_esc"), 3), "preauth_esc": tier(a.get("preauth_esc"), 0)})
}

fn broken_rules(verb: &str) -> Value {
    json!({"v": 1, "verb": verb, "rules_digest": "", "def_digest": "", "tighten": [{"id": "rules_broken", "when": {"field": "action.verb", "op": "eq", "value": verb}, "signal": "deny",
           "reason": "the business rules of this action no longer compile"}], "accumulators": []})
}

struct Entry {
    def: Value,
    reg: usize,
    rules: Option<Value>,
}

/// The verifier's view: `lookup(verb)`, `provenance(op)`, `undo_plan(op)`, `floor(verb, grant, call_context)`.
pub struct HostedView {
    pins: Option<Value>,
    regs: Vec<Registry>,
    by_verb: BTreeMap<String, Entry>,
    deprecated: BTreeSet<String>,
    broken: BTreeSet<String>,
    top: Profile,
    top_ids: Vec<String>,
    prov: BTreeMap<String, Value>,
    pub versions: Vec<String>,
}

pub fn hosted_view(versions: &[Value], pins: Option<&Value>) -> HostedView {
    let pins = pins.filter(|p| !p.is_null()).cloned();
    let (mut regs, mut by_verb): (Vec<Registry>, BTreeMap<String, Entry>) = (vec![], BTreeMap::new());
    let (mut deprecated, mut broken): (BTreeSet<String>, BTreeSet<String>) = (BTreeSet::new(), BTreeSet::new());
    let mut names = Vec::new();
    for v in versions {
        names.push(format!("{}@{}", js_str(&v["ns"]), js_str(&v["version"])));
        let traits: Vec<Value> = v["traits"].as_array().cloned().unwrap_or_default();
        let defs: Vec<Value> = v["pack"]["defs"].as_array().cloned().unwrap_or_default();
        let reg = match registry_of_traits(&traits) {
            Ok(r) => r,
            Err(_) => {
                for d in &defs {
                    if let Some(x) = d.get("verb").and_then(Value::as_str) {
                        broken.insert(x.to_string());
                    }
                }
                continue;
            }
        };
        regs.push(reg);
        for d in &defs {
            let verb = d["verb"].as_str().unwrap_or("").to_string();
            if !by_verb.contains_key(&verb) {
                let rules = v["rules"]["rules"].get(&verb).filter(|r| !r.is_null() && r.as_object().map_or(true, |o| !o.is_empty())).cloned();
                by_verb.insert(verb, Entry { def: d.clone(), reg: regs.len() - 1, rules });
            }
        }
        deprecated.extend(strs_of(v.get("deprecated")));
    }
    for x in deprecated.iter().chain(broken.iter()) {
        by_verb.remove(x);
    }
    let core = core_registry();
    let tops: Vec<Profile> = if regs.is_empty() {
        vec![floor_of(&core, &top_traits(&core)).expect("core registry")]
    } else {
        regs.iter().map(|r| floor_of(r, &top_traits(r)).expect("registry")).collect()
    };
    let top = tops.iter().skip(1).fold(tops[0].clone(), |a, b| join(&a, b));
    let mut top_ids: BTreeSet<String> = BTreeSet::new();
    for r in if regs.is_empty() { std::slice::from_ref(&core) } else { regs.as_slice() } {
        top_ids.extend(top_traits(r));
    }
    let mut top_ids: Vec<String> = top_ids.into_iter().collect();
    sort_u16(&mut top_ids);
    let mut prov = BTreeMap::new();
    for (verb, e) in &by_verb {
        let info = with_verifier(pins.as_ref(), &regs[e.reg], |rv| {
            if safe_confirmed(&e.def, rv) {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| provenance_info_of(&e.def, Some(&regs[e.reg]), rv))).ok()
            } else {
                None
            }
        });
        if let Some(i) = info {
            prov.insert(verb.clone(), i);
        }
    }
    HostedView { pins, regs, by_verb, deprecated, broken, top, top_ids, prov, versions: names }
}

impl HostedView {
    /// Everything the verifier knows about one verb. An unknown, unconfirmed or deprecated verb is the top of the registry.
    pub fn lookup(&self, verb: &str) -> Value {
        let e = self.by_verb.get(verb);
        let mut out = Map::new();
        out.insert("verb".into(), json!(verb));
        out.insert("confirmed".into(), json!(false));
        out.insert("known".into(), json!(e.is_some()));
        out.insert("deprecated".into(), json!(self.deprecated.contains(verb)));
        out.insert("profile".into(), self.top.to_value());
        out.insert("traits".into(), json!(self.top_ids));
        out.insert("serverClass".into(), json!("irreversible"));
        if e.is_none() && self.broken.contains(verb) && !self.deprecated.contains(verb) {
            out.insert("known".into(), json!(true));
            out.insert("rules".into(), broken_rules(verb));
        }
        let Some(e) = e else { return Value::Object(out) };
        let reg = &self.regs[e.reg];
        let attempt = with_verifier(self.pins.as_ref(), reg, |rv| -> Result<Map<String, Value>, String> {
            let eff = effective_with(&e.def, reg, rv).map_err(super::msg)?;
            let confirmed = eff.confirmed;
            let idem = (e.def["idempotency"]["mode"] == "key_param").then(|| e.def["idempotency"]["param"].clone()).filter(|p| !p.is_null());
            let mut nxt = out.clone();
            nxt.insert("def_digest".into(), json!(def_digest(&e.def)));
            nxt.insert("confirmed".into(), json!(confirmed));
            if let Some(p) = idem {
                nxt.insert("idempotency_param".into(), p);
            }
            if confirmed {
                nxt.insert("profile".into(), eff.main.eff.to_value());
                nxt.insert("traits".into(), json!(eff.main.traits));
                let cls = match eff.main.eff.rev.as_str() {
                    "reversible" => "reversible",
                    "rate_limited" => "costly",
                    _ => "irreversible",
                };
                nxt.insert("serverClass".into(), json!(cls));
            }
            if let Some(r) = &e.rules {
                nxt.insert("rules".into(), compile_business_rules(&e.def, r).map_err(super::msg)?);
            }
            Ok(nxt)
        });
        match attempt {
            Ok(m) => Value::Object(m),
            Err(_) => {
                out.insert("confirmed".into(), json!(false));
                out.insert("profile".into(), self.top.to_value());
                out.insert("traits".into(), json!(self.top_ids));
                out.insert("serverClass".into(), json!("irreversible"));
                out.insert("rules".into(), broken_rules(verb));
                Value::Object(out)
            }
        }
    }

    pub fn provenance(&self, op: &Value) -> Option<&Value> {
        self.prov.get(op["verb"].as_str()?)
    }

    pub fn undo_plan(&self, op: &Value) -> Option<Value> {
        let e = self.by_verb.get(op.get("verb")?.as_str()?)?;
        let defs: Vec<Value> = self.by_verb.values().filter(|x| x.reg == e.reg).map(|x| x.def.clone()).collect();
        with_verifier(self.pins.as_ref(), &self.regs[e.reg], |rv| undo_engine(&defs, &self.regs[e.reg], rv).plan(op))
    }

    /// FloorDecision of the grant against the verb's profile; anything undecidable denies.
    pub fn floor(&self, verb: &str, grant: &Value, call_context: &[String]) -> &'static str {
        let (Some(max), Some(pre)) = (grant.get("max_esc").filter(|v| nonneg(v)), grant.get("preauth_esc").filter(|v| nonneg(v))) else { return "deny" };
        let Some(cav) = grant.get("caveats").and_then(Value::as_array) else { return "deny" };
        let kinds: Vec<String> = cav.iter().filter_map(Value::as_str).filter(|c| CAVEAT_KINDS.contains(c)).map(String::from).collect();
        let Some(p) = Profile::from_value(&self.lookup(verb)["profile"]) else { return "deny" };
        floor_decision(&GrantFacts { caveats: kinds, max_esc: max.as_i64().unwrap_or(-1), preauth_esc: pre.as_i64().unwrap_or(-1) }, call_context, &p)
    }
}

/// The context keys the hosted server itself establishes for a call: fresh revocation always; an idempotency key when one is present.
pub fn hosted_call_context(l: Option<&Value>, params: Option<&Value>) -> Vec<String> {
    let mut out = vec!["fresh_revocation".to_string()];
    let k = l.and_then(|l| l.get("idempotency_param")).filter(|k| !k.is_null());
    if let (Some(k), Some(p)) = (k.and_then(Value::as_str), params.filter(|p| !p.is_null())) {
        if p.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
            out.push("idempotency".into());
        }
    }
    out
}

/// The event keys of a rules block's rate limits: verb, window and scope id (never a rule index or the rules digest).
pub fn rate_keys_of(c: &Value, who: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    for a in c["accumulators"].as_array().into_iter().flatten() {
        let scope = if a.get("scope").and_then(Value::as_str) == Some("org") { "org" } else { "principal" };
        let id = who.get(scope).and_then(Value::as_str).filter(|s| !s.is_empty());
        let ms = if a["win"]["kind"] == "task" { 0 } else { a["win"]["ms"].as_i64().unwrap_or(0) };
        let mut e = Map::new();
        e.insert("id".into(), a["id"].clone());
        e.insert("ms".into(), json!(ms));
        if let (Some(i), true) = (id, ms > 0) {
            e.insert("key".into(), json!(format!("{}|{ms}|{scope}:{i}", c["verb"].as_str().unwrap_or(""))));
        }
        out.push(Value::Object(e));
    }
    out
}
