//! Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed
//! packs (with shards), the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures, digests and
//! pins; they do NOT recompute the semantic diff (the tracker checks chain, version and signatures). Pure and total.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::actions::{
    core_registry, def_digest, floor_decision, is_context_key, pack_root, schema_floor_error, tables_digest, traits_digest, utf16_len, validate_def, GrantFacts,
    Profile, CAVEAT_KINDS, CONTEXT_KEYS, PARAM_RULE_IDS,
};
use super::intent_strict::{b32, same, s};
use super::intent_suite::{suite_of, verify_pinned_suite};
use super::{canonicalize_strict, hash_canonical_strict};

pub const EVOLUTION_RECORD_KIND: &str = "pca-evolution-record";
const REAPPROVAL_KIND: &str = "pca-reapproval";
const EVOLUTION_DOMAIN: &str = "atlas-pca/action-evolution/v1\0";
const EVOLUTION_DIFF_DOMAIN: &str = "atlas-pca/action-evolution-diff/v1";
const REAPPROVAL_DOMAIN: &str = "atlas-pca/action-reapproval/v1\0";
const PACK_SIG_DOMAIN: &str = "atlas-pca/action-pack/v1\0";
const PACK_REF_DOMAIN: &str = "atlas-pca/action-pack-ref/v1";
const PACK_SHARD_DOMAIN: &str = "atlas-pca/action-pack-shard/v1";
const RULES_DIGEST_DOMAIN: &str = "atlas-pca/action-rules/v1";
const PACK_KIND: &str = "pca-action-pack";
const PACK_SHARD_KIND: &str = "pca-action-pack-shard";
const MAX_EVOLUTION_STEPS: usize = 32;
const EVOLUTION_CLASSES: [&str; 6] = ["equal", "narrow", "widen", "incomparable", "added", "removed"];
const STABILITIES: [&str; 3] = ["draft", "beta", "stable"];

// ---- helpers ----------------------------------------------------------------------------------------------------------------

fn sha(x: Option<&Value>) -> bool {
    matches!(x, Some(Value::String(v)) if v.len() == 43 && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
}
fn seg_ok(p: &str) -> bool {
    !p.is_empty() && p.bytes().all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}
fn dotted_ok(v: &str, min: usize, max: usize) -> bool {
    let n = v.split('.').count();
    (min..=max).contains(&n) && v.split('.').all(seg_ok)
}
fn ns_ok(x: Option<&Value>) -> bool {
    s(x).is_some_and(|v| dotted_ok(v, 1, 6))
}
fn verb_ok(v: &str) -> bool {
    dotted_ok(v, 2, 6)
}
fn semver_parts(v: &str) -> Option<[u64; 3]> {
    let ps: Vec<&str> = v.split('.').collect();
    if ps.len() != 3 {
        return None;
    }
    let mut out = [0u64; 3];
    for (i, p) in ps.iter().enumerate() {
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        out[i] = p.parse().ok()?;
    }
    Some(out)
}
fn shard_name_ok(v: &str) -> bool {
    let n = v.split(['.', '-']).count();
    (1..=8).contains(&n) && v.split(['.', '-']).all(seg_ok)
}
fn closed(o: &Map<String, Value>, allowed: &[&str]) -> Option<String> {
    o.keys().find(|k| !allowed.contains(&k.as_str())).map(|k| format!("unknown member '{k}'"))
}
fn is_one(v: Option<&Value>) -> bool {
    v.and_then(Value::as_i64) == Some(1)
}
fn tier(v: Option<&Value>) -> bool {
    v.and_then(Value::as_i64).is_some_and(|t| (0..=3).contains(&t))
}
fn u16cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
fn message(domain: &str, body: &Value) -> Option<Vec<u8>> {
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(canonicalize_strict(body).ok()?.as_bytes());
    Some(m)
}
fn without_sig(o: &Map<String, Value>) -> Value {
    let mut b = o.clone();
    b.remove("sig");
    Value::Object(b)
}
fn null_or_absent(v: Option<&Value>) -> bool {
    v.map_or(true, Value::is_null)
}

// ---- evolution records ------------------------------------------------------------------------------------------------------

pub fn evolution_record_error(x: &Value, signed: bool) -> Option<String> {
    let o = match x.as_object() {
        Some(o) => o,
        None => return Some("evolution record must be an object".into()),
    };
    let mut allowed = vec!["v", "kind", "ns", "verb", "from", "to", "class", "reasons"];
    if signed {
        allowed.push("sig");
    }
    if let Some(u) = closed(o, &allowed) {
        return Some(format!("evolution record: {u}"));
    }
    if !is_one(o.get("v")) || s(o.get("kind")) != Some(EVOLUTION_RECORD_KIND) {
        return Some("evolution record: bad v/kind".into());
    }
    if !ns_ok(o.get("ns")) {
        return Some("evolution record: bad ns".into());
    }
    if !s(o.get("verb")).is_some_and(verb_ok) {
        return Some("evolution record: bad verb".into());
    }
    if !null_or_absent(o.get("from")) && !sha(o.get("from")) {
        return Some("evolution record: bad from".into());
    }
    if !null_or_absent(o.get("to")) && !sha(o.get("to")) {
        return Some("evolution record: bad to".into());
    }
    let c = match s(o.get("class")).filter(|c| EVOLUTION_CLASSES.contains(c)) {
        Some(c) => c,
        None => return Some("evolution record: bad class".into()),
    };
    if (c == "added") != null_or_absent(o.get("from")) || (c == "removed") != null_or_absent(o.get("to")) {
        return Some("evolution record: endpoints do not match the class".into());
    }
    match o.get("reasons").and_then(Value::as_array) {
        Some(r) if r.len() <= 64 && r.iter().all(|e| e.as_str().is_some_and(|e| utf16_len(e) <= 512)) => {}
        _ => return Some("evolution record: bad reasons".into()),
    }
    if signed {
        let bad = || Some("evolution record: bad sig".to_string());
        let sg = match o.get("sig").and_then(Value::as_object) {
            Some(sg) if closed(sg, &["alg", "kid", "value", "pq_value"]).is_none() => sg,
            _ => return bad(),
        };
        if !s(sg.get("kid")).is_some_and(|k| (1..=128).contains(&utf16_len(k))) || sg.get("value").and_then(Value::as_str).is_none() || sg.get("alg").and_then(Value::as_str).is_none() {
            return bad();
        }
        if sg.get("pq_value").is_some_and(|p| !p.is_string()) {
            return bad();
        }
    }
    if let Err(e) = canonicalize_strict(&without_sig(o)) {
        return Some(format!("evolution record: {e}"));
    }
    None
}

/// Digest of ONE record's diff; None where a member is absent or out of the strict profile (the reference throws).
pub fn evolution_diff_digest(r: &Value) -> Option<String> {
    let g = |k: &str| r.get(k).cloned();
    hash_canonical_strict(&json!({"d": EVOLUTION_DIFF_DOMAIN, "ns": g("ns")?, "verb": g("verb")?, "from": g("from")?, "to": g("to")?, "class": g("class")?, "reasons": g("reasons")?}))
}

/// Verify a registry-signed body under `domain` against the pinned registry keys (the suite comes from the KEY entry). Total.
pub fn verify_registry_sig(domain: &str, body: &Value, sig: &Map<String, Value>, keys: &Value) -> Result<(), String> {
    let ks = keys.as_array().ok_or("the registry keys must be an array")?;
    let key = ks.iter().filter_map(Value::as_object).find(|k| same(k.get("kid"), sig.get("kid")));
    let key = key.ok_or_else(|| format!("no registry key with kid '{}'", s(sig.get("kid")).unwrap_or("")))?;
    if key.get("pq_pk").is_some_and(|p| !p.is_string()) {
        return Err("the registry key pq_pk must be a string".into());
    }
    if !b32(key.get("pk")) {
        return Err("registry key pk is not canonical base64url (32 bytes)".into());
    }
    let ka = suite_of(key.get("alg")).map_err(|_| "sig.alg does not match the pinned key suite".to_string())?;
    match suite_of(sig.get("alg")) {
        Ok(sa) if sa.alg == ka.alg => {}
        _ => return Err("sig.alg does not match the pinned key suite".into()),
    }
    let pk = s(key.get("pk")).unwrap_or("");
    let pin = key.get("pq_pk").map(|p| (pk, p));
    let msg = message(domain, body).ok_or("verification error: not strictly canonical")?;
    let alg = Value::String(ka.alg.into());
    match verify_pinned_suite(Some(&alg), pk, key.get("pq_pk"), &msg, sig.get("value"), sig.get("pq_value"), pin) {
        Ok(true) => Ok(()),
        _ => Err("signature invalid".into()),
    }
}

pub fn verify_evolution_record(rec: &Value, keys: &Value) -> Result<(), String> {
    if let Some(e) = evolution_record_error(rec, true) {
        return Err(e);
    }
    let o = rec.as_object().unwrap();
    verify_registry_sig(EVOLUTION_DOMAIN, &without_sig(o), o["sig"].as_object().unwrap(), keys)
}

pub fn reapproval_valid(r: &Value, grant_id: &str, issuer: &str, verb: &str, diff: &str) -> bool {
    let o = match r.as_object() {
        Some(o) if closed(o, &["v", "kind", "grant", "verb", "diff", "sig"]).is_none() => o,
        _ => return false,
    };
    if !is_one(o.get("v")) || s(o.get("kind")) != Some(REAPPROVAL_KIND) || s(o.get("grant")) != Some(grant_id) || s(o.get("verb")) != Some(verb) || s(o.get("diff")) != Some(diff) {
        return false;
    }
    let sg = match o.get("sig").and_then(Value::as_object) {
        Some(sg) if closed(sg, &["alg", "value"]).is_none() && s(sg.get("alg")) == Some("ed25519") && sg.get("value").is_some_and(Value::is_string) => sg,
        _ => return false,
    };
    let msg = match message(REAPPROVAL_DOMAIN, &without_sig(o)) {
        Some(m) => m,
        None => return false,
    };
    let alg = Value::String("ed25519".into());
    verify_pinned_suite(Some(&alg), issuer, None, &msg, sg.get("value"), None, None).unwrap_or(false)
}

// ---- the pin ------------------------------------------------------------------------------------------------------------------

pub fn action_pin_error(x: &Value) -> Option<String> {
    let o = match x.as_object() {
        Some(o) => o,
        None => return Some("actions must be an object".into()),
    };
    if let Some(u) = closed(o, &["pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats"]) {
        return Some(format!("actions: {u}"));
    }
    let p = match o.get("pack").and_then(Value::as_object) {
        Some(p) if closed(p, &["ns", "root"]).is_none() => p,
        _ => return Some("actions.pack must be {ns, root}".into()),
    };
    if !ns_ok(p.get("ns")) {
        return Some("actions.pack.ns is not a namespace".into());
    }
    if !sha(p.get("root")) {
        return Some("actions.pack.root must be a base64url digest".into());
    }
    if !matches!(s(o.get("on_new_action")), Some("deny" | "escalate")) {
        return Some("actions.on_new_action must be 'deny' or 'escalate'".into());
    }
    if o.contains_key("max_esc") && !tier(o.get("max_esc")) {
        return Some("actions.max_esc must be an integer tier 0..3".into());
    }
    if o.contains_key("preauth_esc") && !tier(o.get("preauth_esc")) {
        return Some("actions.preauth_esc must be an integer tier 0..3".into());
    }
    if tier(o.get("max_esc")) && tier(o.get("preauth_esc")) && o["preauth_esc"].as_i64() > o["max_esc"].as_i64() {
        return Some("actions.preauth_esc exceeds actions.max_esc".into());
    }
    if let Some(c) = o.get("caveats") {
        let ok = c.as_array().is_some_and(|a| a.iter().all(|k| k.as_str().is_some_and(|k| CAVEAT_KINDS.contains(&k))) && a.iter().filter_map(Value::as_str).collect::<BTreeSet<_>>().len() == a.len());
        if !ok {
            return Some("actions.caveats must be distinct caveat kinds".into());
        }
    }
    if let Some(d) = o.get("defs") {
        let d = match d.as_object() {
            Some(d) => d,
            None => return Some("actions.defs must be an object".into()),
        };
        for (verb, dg) in d {
            if !verb_ok(verb) {
                return Some(format!("actions.defs: '{verb}' is not a verb"));
            }
            if !sha(Some(dg)) {
                return Some(format!("actions.defs.{verb} must be a base64url digest"));
            }
        }
    }
    None
}

fn deny(code: &str, reason: &str, escalate: bool, needs: Option<String>) -> Value {
    let mut o = json!({"ok": false, "code": code, "escalate": escalate, "reason": reason});
    if let Some(n) = needs {
        o["needs_reapproval"] = Value::String(n);
    }
    o
}

type Parents = BTreeMap<String, (String, Option<String>)>;

/// Decide the pin for one verb: exact digest, pack root, or a chain of verified `equal`/`narrow` (or principal-approved) evolution steps.
pub fn decide_pin(i: &Value) -> Value {
    let null = Value::Null;
    let pin = i.get("pin").unwrap_or(&null);
    if let Some(e) = action_pin_error(pin) {
        return deny("bad_pin", &e, false, None);
    }
    let (doc, verb) = (&i["doc"], i["verb"].as_str().unwrap_or(""));
    let found = doc.get("verbs").and_then(Value::as_array).and_then(|vs| vs.iter().find(|x| x.is_object() && x.get("verb").and_then(Value::as_str) == Some(verb)));
    let v = match found {
        Some(v) => v,
        None => return deny("unknown_verb", &format!("the accepted schema does not declare '{verb}'"), false, None),
    };
    let pns = pin["pack"]["ns"].as_str().unwrap_or("");
    let pk = doc.get("pack").and_then(Value::as_object);
    if !pk.is_some_and(|p| p.get("ns").and_then(Value::as_str) == Some(pns)) {
        return deny("pack_mismatch", &format!("the schema does not come from the pinned pack '{pns}'"), false, None);
    }
    let pk = pk.unwrap();
    let defs = match pin.get("defs").and_then(Value::as_object) {
        Some(d) => d,
        None => {
            return if pk.get("root").is_some() && pk.get("root") == pin["pack"].get("root") {
                json!({"ok": true, "via": "pack"})
            } else {
                deny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)", false, None)
            }
        }
    };
    let on_new = pin["on_new_action"].as_str().unwrap_or("");
    let pinned = match defs.get(verb).and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return deny("new_action", &format!("the grant does not name '{verb}' (on_new_action: {on_new})"), on_new == "escalate", None),
    };
    let presented = match v.get("def").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return deny("def_changed", "the schema verb carries no definition digest", false, None),
    };
    if presented == pinned {
        return json!({"ok": true, "via": "exact"});
    }
    let empty = Vec::new();
    let keys = i.get("keys").filter(|k| !k.is_null()).cloned().unwrap_or(json!([]));
    let (gid, gis) = (i["grant"]["id"].as_str().unwrap_or(""), i["grant"]["issuer"].as_str().unwrap_or(""));
    let reapprovals = i.get("reapprovals").and_then(Value::as_array).unwrap_or(&empty);
    let mut edges: BTreeMap<String, Vec<(String, Option<String>)>> = BTreeMap::new();
    for r in i.get("records").and_then(Value::as_array).unwrap_or(&empty) {
        if verify_evolution_record(r, &keys).is_err() {
            continue;
        }
        let (rns, rverb, from, to) = (s(r.get("ns")), s(r.get("verb")), s(r.get("from")), s(r.get("to")));
        if rns != Some(pns) || rverb != Some(verb) || from.is_none() || to.is_none() {
            continue;
        }
        let diff = match evolution_diff_digest(r) {
            Some(d) => d,
            None => continue,
        };
        let free = matches!(s(r.get("class")), Some("equal" | "narrow"));
        let approved = free || reapprovals.iter().any(|a| reapproval_valid(a, gid, gis, verb, &diff));
        edges.entry(from.unwrap().into()).or_default().push((to.unwrap().into(), if approved { None } else { Some(diff) }));
    }
    let search = |usable_only: bool| -> Parents {
        let mut parent: Parents = BTreeMap::new();
        let mut seen: BTreeSet<String> = BTreeSet::from([pinned.clone()]);
        let mut frontier = vec![pinned.clone()];
        let mut step = 0;
        while step < MAX_EVOLUTION_STEPS && !frontier.is_empty() && !parent.contains_key(&presented) {
            let mut next = Vec::new();
            for f in &frontier {
                for (to, blocked) in edges.get(f).into_iter().flatten() {
                    if seen.contains(to) || (usable_only && blocked.is_some()) {
                        continue;
                    }
                    seen.insert(to.clone());
                    parent.insert(to.clone(), (f.clone(), blocked.clone()));
                    next.push(to.clone());
                }
            }
            frontier = next;
            step += 1;
        }
        parent
    };
    if search(true).contains_key(&presented) {
        return json!({"ok": true, "via": "chain"});
    }
    let all = search(false);
    if all.contains_key(&presented) {
        let (mut first, mut cur) = (None, presented.clone());
        while cur != pinned {
            let (from, blocked) = &all[&cur];
            if blocked.is_some() {
                first = blocked.clone();
            }
            cur = from.clone();
        }
        return deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", false, first);
    }
    deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it", false, None)
}

// ---- signed packs -------------------------------------------------------------------------------------------------------------

pub fn compare_versions(a: &str, b: &str) -> Result<i64, String> {
    let pa = semver_parts(a).ok_or_else(|| format!("'{a}' is not MAJOR.MINOR.PATCH"))?;
    let pb = semver_parts(b).ok_or_else(|| format!("'{b}' is not MAJOR.MINOR.PATCH"))?;
    for k in 0..3 {
        if pa[k] != pb[k] {
            return Ok(pa[k] as i64 - pb[k] as i64);
        }
    }
    Ok(0)
}

pub fn rules_digest() -> String {
    hash_canonical_strict(&json!({"d": RULES_DIGEST_DOMAIN, "prules": PARAM_RULE_IDS, "caveats": CAVEAT_KINDS, "context": CONTEXT_KEYS})).unwrap()
}
pub fn pack_digest(p: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": PACK_REF_DOMAIN, "p": p}))
}
pub fn shard_digest(sh: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": PACK_SHARD_DOMAIN, "s": sh}))
}

fn sorted_unique_defs_error(defs: &[Value]) -> Option<String> {
    for (i, d) in defs.iter().enumerate() {
        if let Some(e) = validate_def(d) {
            return Some(format!("def {i}: {e}"));
        }
        let verb = d["verb"].as_str().unwrap_or("");
        if i > 0 && u16cmp(defs[i - 1]["verb"].as_str().unwrap_or(""), verb) != std::cmp::Ordering::Less {
            return Some(format!("defs must be sorted by verb and unique (at '{verb}')"));
        }
    }
    None
}

pub fn pack_shape_error(x: &Value) -> Option<String> {
    let o = match x.as_object() {
        Some(o) => o,
        None => return Some("pack must be an object".into()),
    };
    if let Some(e) = closed(o, &["v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution", "sig"]) {
        return Some(format!("pack: {e}"));
    }
    if !is_one(o.get("v")) || s(o.get("kind")) != Some(PACK_KIND) {
        return Some("pack: bad v/kind".into());
    }
    if !ns_ok(o.get("ns")) {
        return Some("pack: bad ns".into());
    }
    if !s(o.get("version")).is_some_and(|v| semver_parts(v).is_some()) {
        return Some("pack: version must be MAJOR.MINOR.PATCH".into());
    }
    if !s(o.get("stability")).is_some_and(|v| STABILITIES.contains(&v)) {
        return Some("pack: bad stability".into());
    }
    for k in ["traits_digest", "roles_digest", "rules_digest", "root"] {
        if !sha(o.get(k)) {
            return Some(format!("pack: {k} must be a base64url digest"));
        }
    }
    if !null_or_absent(o.get("prev")) && !sha(o.get("prev")) {
        return Some("pack: bad prev".into());
    }
    let src = match o.get("source").and_then(Value::as_object) {
        Some(sr) if closed(sr, &["kind", "uri", "spec_digest", "licence", "licence_notes"]).is_none() => sr,
        _ => return Some("pack: source must be {kind, uri, spec_digest, licence, licence_notes}".into()),
    };
    for k in ["kind", "uri", "spec_digest", "licence", "licence_notes"] {
        let ok = src.get(k).and_then(Value::as_str).is_some_and(|v| (k == "licence_notes" || !v.is_empty()) && utf16_len(v) <= 2048);
        if !ok {
            return Some(format!("pack: source.{k} is not a string of 1..2048 characters"));
        }
    }
    match o.get("defs") {
        Some(Value::Array(d)) => {
            if d.is_empty() || d.len() > 4096 {
                return Some("pack: inline defs must number 1..4096 (larger packs are sharded)".into());
            }
            if let Some(e) = sorted_unique_defs_error(d) {
                return Some(format!("pack: {e}"));
            }
        }
        other => {
            let sh = match other.and_then(Value::as_object).filter(|d| closed(d, &["shards"]).is_none()).and_then(|d| d.get("shards")).and_then(Value::as_array) {
                Some(a) if !a.is_empty() && a.len() <= 4096 => a,
                _ => return Some("pack: defs must be a list of defs or {shards}".into()),
            };
            let mut names = BTreeSet::new();
            for r in sh {
                let r = match r.as_object() {
                    Some(r) if closed(r, &["name", "digest", "uri"]).is_none() => r,
                    _ => return Some("pack: bad shard ref".into()),
                };
                let name = s(r.get("name"));
                if !name.is_some_and(shard_name_ok) || !names.insert(name.unwrap().to_string()) {
                    return Some("pack: shard names must be distinct simple names".into());
                }
                if !sha(r.get("digest")) || !s(r.get("uri")).is_some_and(|u| !u.is_empty() && utf16_len(u) <= 2048) {
                    return Some("pack: bad shard digest or uri".into());
                }
            }
        }
    }
    match o.get("evolution").and_then(Value::as_array) {
        Some(ev) if ev.len() <= 65536 => {
            for r in ev {
                if let Some(e) = evolution_record_error(r, true) {
                    return Some(format!("pack: {e}"));
                }
            }
        }
        _ => return Some("pack: evolution must be a list of records".into()),
    }
    let sig_ok = o.get("sig").and_then(Value::as_object).is_some_and(|g| {
        closed(g, &["alg", "kid", "value", "pq_value"]).is_none() && g.get("kid").is_some_and(Value::is_string) && g.get("value").is_some_and(Value::is_string) && g.get("alg").is_some_and(Value::is_string)
    });
    if !sig_ok {
        return Some("pack: bad sig".into());
    }
    if let Err(e) = canonicalize_strict(&without_sig(o)) {
        return Some(format!("pack: {e}"));
    }
    None
}

/// The defs a pack lists (inline, or gathered from its shards).
pub fn pack_defs(pack: &Value, shards: Option<&Value>) -> Result<Vec<Value>, String> {
    if let Some(a) = pack["defs"].as_array() {
        return Ok(a.clone());
    }
    let mut all = Vec::new();
    for r in pack["defs"]["shards"].as_array().into_iter().flatten() {
        let name = r["name"].as_str().unwrap_or("");
        let sh = shards.and_then(Value::as_object).and_then(|m| m.get(name)).ok_or_else(|| format!("shard '{name}' was not supplied"))?;
        if shard_digest(sh).as_deref() != r["digest"].as_str() {
            return Err(format!("shard '{name}' does not match its digest"));
        }
        let ok = is_one(sh.get("v")) && s(sh.get("kind")) == Some(PACK_SHARD_KIND) && sh.get("ns") == pack.get("ns") && sh.get("version") == pack.get("version") && s(sh.get("name")) == Some(name) && sh.get("defs").is_some_and(Value::is_array);
        if !ok {
            return Err(format!("shard '{name}' is not a shard of this pack"));
        }
        all.extend(sh["defs"].as_array().unwrap().iter().cloned());
    }
    all.sort_by(|a, b| u16cmp(a["verb"].as_str().unwrap_or(""), b["verb"].as_str().unwrap_or("")));
    Ok(all)
}

/// Shape, signature under the pinned registry keys, vocabulary digests, shards, defs, the recomputed Merkle root, and every
/// evolution record. `Ok((digest, defs))`.
pub fn verify_pack(pack: &Value, keys: &Value, shards: Option<&Value>) -> Result<(String, Vec<Value>), String> {
    if let Some(e) = pack_shape_error(pack) {
        return Err(e);
    }
    let o = pack.as_object().unwrap();
    verify_registry_sig(PACK_SIG_DOMAIN, &without_sig(o), o["sig"].as_object().unwrap(), keys).map_err(|r| format!("pack signature: {r}"))?;
    if s(o.get("traits_digest")) != Some(traits_digest(&core_registry()).as_str()) {
        return Err("traits_digest does not match the trait registry".into());
    }
    if s(o.get("roles_digest")) != Some(tables_digest().as_str()) {
        return Err("roles_digest does not match the vocabulary tables".into());
    }
    if s(o.get("rules_digest")) != Some(rules_digest().as_str()) {
        return Err("rules_digest does not match the rule tables".into());
    }
    let defs = pack_defs(pack, shards)?;
    if let Some(e) = sorted_unique_defs_error(&defs) {
        return Err(e);
    }
    if defs.is_empty() || defs.len() > 1_000_000 {
        return Err("the pack lists no defs or too many".into());
    }
    let digests: Vec<String> = defs.iter().map(|d| def_digest(d).unwrap_or_default()).collect();
    if pack_root(&digests).map_err(|e| e.to_string())? != o["root"].as_str().unwrap_or("") {
        return Err("the Merkle root does not match the defs".into());
    }
    let have: BTreeSet<&str> = digests.iter().map(String::as_str).collect();
    for r in o["evolution"].as_array().unwrap() {
        verify_evolution_record(r, keys).map_err(|e| format!("evolution record: {e}"))?;
        if r["ns"] != o["ns"] {
            return Err("evolution record of another namespace".into());
        }
        if let Some(to) = r["to"].as_str() {
            if !have.contains(to) {
                return Err(format!("evolution record for '{}' names a definition that is not in the pack", r["verb"].as_str().unwrap_or("")));
            }
        }
    }
    Ok((pack_digest(pack).ok_or("pack digest")?, defs))
}

/// The verifier's view of a registry: refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed.
pub struct PackTracker {
    keys: Value,
    seen: BTreeMap<String, (String, String)>,
}
impl PackTracker {
    pub fn new(keys: Value) -> Self {
        PackTracker { keys, seen: BTreeMap::new() }
    }
    /// `Ok(status)` or `Err(code)`.
    pub fn accept(&mut self, pack: &Value, shards: Option<&Value>) -> Result<&'static str, &'static str> {
        let (digest, _) = verify_pack(pack, &self.keys, shards).map_err(|_| "bad_pack")?;
        let (ns, version) = (pack["ns"].as_str().unwrap().to_string(), pack["version"].as_str().unwrap().to_string());
        let cur = match self.seen.get(&ns) {
            None => {
                self.seen.insert(ns, (version, digest));
                return Ok("first");
            }
            Some(c) => c.clone(),
        };
        if cur.1 == digest {
            return Ok("same");
        }
        let c = compare_versions(&version, &cur.0).map_err(|_| "bad_pack")?;
        if c < 0 {
            return Err("rollback");
        }
        if c == 0 {
            return Err("fork");
        }
        if pack["prev"].as_str() != Some(cur.1.as_str()) {
            return Err("chain_gap");
        }
        self.seen.insert(ns, (version, digest));
        Ok("upgrade")
    }
}

// ---- rule 22 over a whole document ---------------------------------------------------------------------------------------------

const CODES: [&str; 5] = ["schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry"];

/// `Ok(())` or `Err(code)`. `pins` = the verifier's pinned reviewer keys; without them no verb is confirmed.
pub fn rule22_integrity(doc: &Value, pins: Option<&Value>) -> Result<(), &'static str> {
    match schema_floor_error(doc, pins) {
        None => Ok(()),
        Some(e) => Err(CODES.iter().find(|c| e.contains(**c)).copied().unwrap_or("unknown")),
    }
}

pub fn rule22_decide(doc: &Value, verb: &str, grant: &Value, context: &Value) -> &'static str {
    let v = doc.get("verbs").and_then(Value::as_array).and_then(|vs| vs.iter().find(|x| x.get("verb").and_then(Value::as_str) == Some(verb)));
    let floors = match v.and_then(|v| v.get("floors")).and_then(Profile::from_value) {
        Some(f) => f,
        None => return "deny",
    };
    let strs = |v: &Value, keep: &dyn Fn(&str) -> bool| -> Vec<String> { v.as_array().into_iter().flatten().filter_map(Value::as_str).filter(|k| keep(k)).map(String::from).collect() };
    let (max_esc, preauth_esc) = match (grant["max_esc"].as_i64(), grant["preauth_esc"].as_i64()) {
        (Some(a), Some(b)) => (a, b),
        _ => return "deny",
    };
    let g = GrantFacts { caveats: strs(&grant["caveats"], &|k| CAVEAT_KINDS.contains(&k)), max_esc, preauth_esc };
    floor_decision(&g, &strs(context, &is_context_key), &floors)
}
