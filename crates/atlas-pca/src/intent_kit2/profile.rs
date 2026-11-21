//! Portable, revocable intent profiles: the principal's signed, versioned record of standing rules and prior answers, append-only
//! succession, scoped use (deny wins, permit is explicit, negative observations veto) and revocation. Signing is Ed25519; a suite-agile
//! profile verifies under the verifier's pin. Profiles, uses and actions are plain JSON.
use super::omega::*;
use super::util::*;
use crate::intent_revocation::{check_session_revocation, profile_revocation_id};
use crate::intent_suite::{bind_suite_fields, domain_message, suite_of, verify_pinned_suite};
use crate::predicates::{predicate_matches, Ctx};
use serde_json::{json, Map, Value};

pub const INTENT_PROFILE_KIND: &str = "pca-intent-profile";
pub const INTENT_PROFILE_SIG_DOMAIN: &str = "atlas-pca/intent-profile/v1\0";
pub const INTENT_PROFILE_REF_DOMAIN: &str = "atlas-pca/intent-profile-ref/v1";
const MAX_PROFILE_RULES: usize = 256;
const MAX_PROFILE_OBSERVATIONS: usize = 2000;
const KEYS: [&str; 15] =
    ["v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg", "pq_pk", "sig", "pq_sig"];

fn is_b32(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).and_then(|s| crate::decode_b64u_strict(s, Some(32))).is_some()
}

fn str_list(v: &Value) -> bool {
    match v.as_array() {
        Some(a) => a.len() <= 256 && a.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())),
        None => false,
    }
}

fn pred_ok(p: &Value) -> bool {
    if !p.is_object() {
        return false;
    }
    match &p["verb"] {
        Value::String(_) => true,
        Value::Array(a) => a.iter().all(Value::is_string),
        _ => false,
    }
}

fn sorted_keys(o: &Map<String, Value>) -> String {
    let mut k = js_keys(o);
    sort_u16(&mut k);
    k.join(",")
}

fn id_ok(s: &str) -> bool {
    let n = s.chars().count();
    (1..=128).contains(&n) && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

fn nonneg_int(v: &Value) -> bool {
    is_safe_int(v) && fnum(v).is_some_and(|x| x >= 0.0)
}

/// `None` when the profile is well-formed (closed, strictly typed); else the first problem.
pub fn intent_profile_shape_error(p: &Value, signed: bool) -> Option<String> {
    let po = match p.as_object() {
        Some(o) => o,
        None => return Some("profile is not an object".into()),
    };
    for k in js_keys(po) {
        if !KEYS.contains(&k.as_str()) {
            return Some(format!("profile: unknown member '{k}'"));
        }
    }
    if fnum(&p["v"]) != Some(1.0) || p["kind"].as_str() != Some(INTENT_PROFILE_KIND) {
        return Some("not a pca-intent-profile v1".into());
    }
    if !p["profile_id"].as_str().is_some_and(id_ok) {
        return Some("profile_id must match [A-Za-z0-9_.-]{1,128}".into());
    }
    if !(is_safe_int(&p["version"]) && fnum(&p["version"]).is_some_and(|x| x >= 1.0)) {
        return Some("version must be a safe integer >= 1".into());
    }
    if !is_b32(po.get("owner")) {
        return Some("owner must be canonical base64url (32 bytes)".into());
    }
    let scope = match p["scope"].as_object() {
        Some(s) if js_keys(s).iter().all(|k| matches!(k.as_str(), "sites" | "verbs" | "semantic_types")) => s,
        _ => return Some("scope must be {sites?, verbs?, semantic_types?}".into()),
    };
    for k in ["sites", "verbs", "semantic_types"] {
        if let Some(v) = scope.get(k) {
            if !str_list(v) {
                return Some(format!("scope.{k} must be a list of strings"));
            }
        }
    }
    let standing = match p["standing"].as_object() {
        Some(s) if sorted_keys(s) == "deny,permit" => s,
        _ => return Some("standing must be {deny, permit}".into()),
    };
    for k in ["deny", "permit"] {
        match standing[k].as_array() {
            Some(r) if r.len() <= MAX_PROFILE_RULES && r.iter().all(pred_ok) => {}
            _ => return Some(format!("standing.{k} must be at most {MAX_PROFILE_RULES} predicates")),
        }
    }
    let prior = match p["prior"].as_object() {
        Some(s) if sorted_keys(s) == "maps,observations" => s,
        _ => return Some("prior must be {observations, maps}".into()),
    };
    let obs = match prior["observations"].as_array() {
        Some(a) if a.len() <= MAX_PROFILE_OBSERVATIONS => a,
        _ => return Some(format!("prior.observations must be at most {MAX_PROFILE_OBSERVATIONS}")),
    };
    for o in obs {
        let ok = match o.as_object() {
            Some(m) => {
                sorted_keys(m) == "at,values,verb,y"
                    && o["verb"].is_string()
                    && o["values"].is_object()
                    && (fnum(&o["y"]) == Some(0.0) || fnum(&o["y"]) == Some(1.0))
                    && nonneg_int(&o["at"])
            }
            None => false,
        };
        if !ok {
            return Some("prior.observations entries are {verb, values, y, at}".into());
        }
    }
    match prior["maps"].as_array() {
        Some(a) if a.iter().all(|m| is_b32(Some(m))) => {}
        _ => return Some("prior.maps must be 32-byte digests".into()),
    }
    if !nonneg_int(&p["expires_at"]) {
        return Some("expires_at must be a non-negative safe integer".into());
    }
    let rev = match p["revocation"].as_object() {
        Some(r) if r.keys().all(|k| k == "epoch_uri" || k == "key") && r.get("epoch_uri").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) => r,
        _ => return Some("revocation must be {epoch_uri, key?}".into()),
    };
    if let Some(k) = rev.get("key") {
        if !is_b32(Some(k)) {
            return Some("revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)".into());
        }
    }
    let prev = po.get("prev");
    if (fnum(&p["version"]) == Some(1.0)) != prev.is_none() {
        return Some("prev is required exactly when version > 1".into());
    }
    if let Some(pv) = prev {
        if !is_b32(Some(pv)) {
            return Some("prev must be canonical base64url (32 bytes)".into());
        }
    }
    if signed {
        let alg = po.get("alg");
        if alg.is_some_and(|a| !a.is_string()) {
            return Some("alg must be a string".into());
        }
        if let Err(e) = suite_of(alg) {
            return Some(format!("alg: {e}"));
        }
        if (alg.is_none() || alg.and_then(Value::as_str) == Some("ed25519")) && (po.contains_key("pq_pk") || po.contains_key("pq_sig")) {
            return Some("an ed25519 profile must not carry pq_pk / pq_sig".into());
        }
        if !p["sig"].is_string() {
            return Some("sig must be a string".into());
        }
    }
    if let Err(e) = crate::canonicalize_strict(&Value::Object(profile_body(p))) {
        return Some(format!("malformed profile: {e}"));
    }
    None
}

fn profile_body(p: &Value) -> Map<String, Value> {
    let mut b = Map::new();
    for k in ["v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev"] {
        if let Some(v) = member(p, k) {
            b.insert(k.to_string(), v.clone());
        }
    }
    b
}

/// Sign a profile version as its owner (Ed25519; the owner identity must be the signer's key).
pub fn sign_intent_profile(body: &Value, seed_b64u: &str) -> R<Value> {
    use ed25519_dalek::{Signer, SigningKey};
    let seed: [u8; 32] =
        crate::decode_b64u_strict(seed_b64u, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or("secret key must be a 32-byte seed")?;
    let sk = SigningKey::from_bytes(&seed);
    let owner = crate::b64_encode(&sk.verifying_key().to_bytes());
    if let Some(o) = member(body, "owner") {
        if o.as_str() != Some(owner.as_str()) {
            return Err("signIntentProfile: owner does not match the signing key".into());
        }
    }
    let mut with = body.as_object().cloned().unwrap_or_default();
    with.insert("owner".into(), json!(owner));
    let b = profile_body(&Value::Object(with));
    if let Some(bad) = intent_profile_shape_error(&Value::Object(b.clone()), false) {
        return Err(format!("signIntentProfile: {bad}"));
    }
    let msg = domain_message(INTENT_PROFILE_SIG_DOMAIN, b.clone()).ok_or("profile is not canonicalizable")?;
    let mut out = b;
    out.insert("sig".into(), json!(crate::b64_encode(&sk.sign(&msg).to_bytes())));
    Ok(Value::Object(out))
}

/// `{ok}` or `{ok: false, reason}`; `pin` carries the optional `pqPins` (identity -> pinned PQ key).
pub fn verify_intent_profile(p: &Value, pin: Option<&Value>) -> Value {
    let fail = |r: &str| json!({"ok": false, "reason": r});
    if let Some(bad) = intent_profile_shape_error(p, true) {
        return fail(&bad);
    }
    let mut body = profile_body(p);
    match bind_suite_fields(&mut body, p.get("alg"), p.get("pq_pk")) {
        Ok(true) => {}
        _ => return fail("malformed profile: canonicalize: unsupported type undefined"),
    }
    let msg = match domain_message(INTENT_PROFILE_SIG_DOMAIN, body) {
        Some(m) => m,
        None => return fail("malformed profile: the profile is not canonicalizable"),
    };
    let owner = p["owner"].as_str().unwrap_or("");
    let pq = pin.and_then(|x| member(x, "pqPins")).filter(|x| x.is_object()).and_then(|pins| member(pins, owner)).map(|v| (owner, v));
    match verify_pinned_suite(p.get("alg"), owner, p.get("pq_pk"), &msg, p.get("sig"), p.get("pq_sig"), pq) {
        Ok(true) => json!({"ok": true}),
        _ => fail("profile signature invalid"),
    }
}

/// The content address of a signed profile version.
pub fn intent_profile_digest(p: &Value) -> R<String> {
    crate::hash_canonical_strict(&json!({"d": INTENT_PROFILE_REF_DOMAIN, "p": p})).ok_or_else(|| "the profile is not canonicalizable".to_string())
}

/// Append-only succession: same id and owner, version + 1, prev = digest(previous).
pub fn verify_profile_succession(prev: &Value, next: &Value) -> Value {
    for (x, n) in [(prev, "previous"), (next, "next")] {
        let v = verify_intent_profile(x, None);
        if v["ok"] != json!(true) {
            return json!({"ok": false, "reason": format!("{n} version: {}", js_str(&v["reason"]))});
        }
    }
    let no = |r: &str| json!({"ok": false, "reason": r});
    if next["profile_id"] != prev["profile_id"] || next["owner"] != prev["owner"] {
        return no("a profile version cannot change its id or owner");
    }
    if fnum(&next["version"]).zip(fnum(&prev["version"])).map_or(true, |(a, b)| a != b + 1.0) {
        return no("versions are append-only: next.version must be previous + 1");
    }
    match intent_profile_digest(prev) {
        Ok(d) if next.get("prev").and_then(Value::as_str) == Some(d.as_str()) => json!({"ok": true}),
        _ => no("next.prev is not the digest of the previous version"),
    }
}

fn lt(a: Option<&Value>, b: &Value) -> bool {
    match (a.and_then(fnum), fnum(b)) {
        (Some(x), Some(y)) => x < y,
        _ => false,
    }
}

fn listed(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

fn any_strict(list: &Value, x: Option<&Value>) -> bool {
    list.as_array().is_some_and(|a| a.iter().any(|t| strict_eq(Some(t), x)))
}

/// Is the profile in scope (and unexpired) for this action?
pub fn profile_applies(p: &Value, u: &Value) -> bool {
    if !lt(member(u, "now"), &p["expires_at"]) {
        return false;
    }
    let scope = &p["scope"];
    if let Some(sites) = listed(member(scope, "sites")) {
        if !any_strict(sites, member(u, "aud")) {
            return false;
        }
    }
    if let Some(verbs) = listed(member(scope, "verbs")) {
        if !any_strict(verbs, member(u, "verb")) {
            return false;
        }
    }
    if let Some(sem) = listed(member(scope, "semantic_types")) {
        let sems = listed(member(u, "semantics")).and_then(Value::as_array).cloned().unwrap_or_default();
        if !sems.iter().any(|s| any_strict(sem, Some(s))) {
            return false;
        }
    }
    true
}

fn any_matches(rules: &Value, ctx: &Value) -> bool {
    let c = Ctx::new(ctx);
    rules.as_array().is_some_and(|a| a.iter().any(|r| predicate_matches(r, &c)))
}

/// G^std membership: an in-scope action is outside the standing layer iff a deny rule matches it (deny wins). `ctx` is `{action, subject?, env?}`.
pub fn standing_admits(p: &Value, u: &Value, ctx: &Value) -> bool {
    if !profile_applies(p, u) {
        return true;
    }
    !any_matches(&p["standing"]["deny"], ctx)
}

/// The explicit standing-permission layer: an in-scope permit rule matches (the only positive import).
pub fn standing_permits(p: &Value, u: &Value, ctx: &Value) -> bool {
    profile_applies(p, u) && any_matches(&p["standing"]["permit"], ctx)
}

/// The cells that the profile's negative observations veto: `[{verb, cell}]`.
pub fn profile_veto_cells(p: &Value, omega: &Omega) -> R<Value> {
    let mut out: Vec<Value> = vec![];
    let mut seen: Vec<String> = vec![];
    for o in arr(&p["prior"]["observations"], "prior.observations")? {
        if fnum(&o["y"]) == Some(0.0) {
            let verb = js_str(&o["verb"]);
            let cell = omega.vs_of(&verb).and_then(|vs| vs.cell_of(&json!({"verb": o["verb"], "values": o["values"]})));
            if let Some(cell) = cell {
                let k = format!("{verb}|{}", cell.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","));
                if !seen.contains(&k) {
                    seen.push(k);
                    out.push(json!({"verb": verb, "cell": cell}));
                }
            }
        }
    }
    Ok(Value::Array(out))
}

/// A ceiling test (for a visit decision) from the profile's standing deny rules over outcomes: true when the outcome is admitted.
pub fn profile_ceiling(p: &Value, u: &Value, vs: &Vs, o: &Value) -> R<bool> {
    let a = outcome_to_action(vs.reversibility.as_deref(), o)?;
    let mut action = Map::new();
    action.insert("verb".into(), a["verb"].clone());
    action.insert("resource".into(), a["resource"].clone());
    action.insert("params".into(), a["params"].clone());
    let mut ctx = Map::new();
    ctx.insert("action".into(), Value::Object(action));
    if let Some(e) = member(&a, "env").filter(|x| truthy(x)) {
        ctx.insert("env".into(), e.clone());
    }
    if let Some(s) = member(&a, "subject").filter(|x| truthy(x)) {
        ctx.insert("subject".into(), s.clone());
    }
    let mut uu = u.as_object().cloned().unwrap_or_default();
    uu.insert("verb".into(), o["verb"].clone());
    Ok(standing_admits(p, &Value::Object(uu), &Value::Object(ctx)))
}

/// Is this profile version usable now: signed, unexpired, and not revoked per a fresh epoch of its revocation authority.
pub fn profile_usable(p: &Value, c: &Value) -> Value {
    let v = verify_intent_profile(p, member(c, "pin"));
    if v["ok"] != json!(true) {
        return v;
    }
    if !lt(member(c, "now"), &p["expires_at"]) {
        return json!({"ok": false, "reason": "the profile has expired"});
    }
    let rev = &p["revocation"];
    let owner = p["owner"].as_str().unwrap_or("");
    let authority = nn(rev, "key").and_then(Value::as_str).unwrap_or(owner);
    let pid = js_str(&p["profile_id"]);
    let ids = [profile_revocation_id(&pid, &js_str(&p["version"]))];
    let pins = member(c, "pin").and_then(|x| member(x, "pqPins")).filter(|x| x.is_object());
    let apq = pins.and_then(|x| member(x, authority));
    let scope = format!("pca-intent-profile:{pid}");
    let now = member(c, "now").and_then(fnum).unwrap_or(f64::NAN);
    let max_age = member(c, "maxAgeMs").and_then(fnum).unwrap_or(f64::NAN);
    match check_session_revocation(member(c, "revocation"), &pid, authority, &ids, now, max_age, Some(scope.as_str()), apq, member(c, "last")) {
        Ok(()) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "reason": format!("profile revocation: {e}")}),
    }
}
