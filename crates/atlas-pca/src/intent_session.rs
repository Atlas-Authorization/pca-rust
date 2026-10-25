//! Intent sessions (Intent Layer v2 rule 13): the signed PCActn member `intent_session` (wire), the session grant
//! caveat, and the principal-signed session root S. Mirrors `packages/pca/src/intent-session.ts` and
//! `intent-session-caveat.ts`.

use serde_json::{Map, Value};

use super::intent_acc::{accumulator_decl_error, monitor_decl_error, MAX_SESSION_ACCUMULATORS, MAX_SESSION_MONITORS};
use super::intent_strict::*;
use super::intent_suite::{bind_suite_fields, domain_message, optional_alg_error, suite_of, suite_shape_error, verify_pinned_suite};

pub(crate) const INTENT_SESSION_KIND: &str = "pca-intent-session";
pub(crate) const INTENT_SESSION_SIG_DOMAIN: &str = "atlas-pca/intent-session/v1\0";
pub(crate) const INTENT_SESSION_REF_DOMAIN: &str = "atlas-pca/intent-session-ref/v1";
/// Largest delta sequence number (2^31 - 1).
pub const MAX_SESSION_SEQ: i64 = 2_147_483_647;
pub(crate) const INTENT_SESSION_CAVEAT: &str = "intent_session";
const MAX_IS_ACC: usize = 16;
const MAX_IS_FACTS: usize = 16;
const MAX_IS_PROV_PATHS: usize = 32;
const MAX_IS_PROV_REFS: usize = 8;
const MAX_IS_CLASSES: usize = 8;
const MAX_IS_LABELS: usize = 16;
const MAX_IS_STRING_BYTES: usize = 256;
const MAX_SESSION_PRINCIPALS: usize = 16;
const INTENT_SESSION_FIELDS: [&str; 11] = ["session", "root", "seq", "schema", "acc", "facts", "offer_set", "prov", "classes", "labels", "map_form"];
/// The only `intent_session.map_form` (rule 19: `intent.map_digest` is the salted map commitment, the goal `v2c`).
pub const MAP_FORM_COMMIT: &str = "commit";
const ROOT_KEYS: [&str; 18] = [
    "v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "revocation", "flows",
    "expires_at", "signer", "alg", "pq_pk", "sig", "pq_sig",
];

fn digest_list(v: &Value, name: &str, max: usize) -> Result<(), String> {
    let a = match v.as_array() {
        Some(a) if a.len() <= max => a,
        _ => return Err(format!("'intent_session.{name}' must be an array of at most {max} digests")),
    };
    if !a.iter().all(|x| b32(Some(x))) {
        return Err(format!("'intent_session.{name}' entries must be canonical base64url (32 bytes)"));
    }
    let distinct: std::collections::BTreeSet<&str> = a.iter().filter_map(Value::as_str).collect();
    if distinct.len() != a.len() {
        return Err(format!("'intent_session.{name}' entries must be distinct"));
    }
    Ok(())
}

/// Wire validation of the PCActn member `intent_session` (rule 13; part of the terminal `wire` check).
pub fn validate_intent_session_wire(v: &Value) -> Result<(), String> {
    let o = v.as_object().ok_or("'intent_session' must be an object")?;
    if let Some(k) = o.keys().find(|k| !INTENT_SESSION_FIELDS.contains(&k.as_str())) {
        return Err(format!("unknown field 'intent_session.{k}'"));
    }
    for k in ["session", "root", "seq", "schema"] {
        if !o.contains_key(k) {
            return Err(format!("missing field 'intent_session.{k}'"));
        }
    }
    for k in ["session", "root", "schema"] {
        if !b32(o.get(k)) {
            return Err(format!("'intent_session.{k}' is not canonical base64url (32 bytes)"));
        }
    }
    if !nonneg(o.get("seq")).is_some_and(|q| q <= MAX_SESSION_SEQ) {
        return Err("'intent_session.seq' must be a safe integer in [0, 2147483647]".into());
    }
    if let Some(acc) = o.get("acc") {
        let a = match acc.as_array() {
            Some(a) if a.len() <= MAX_IS_ACC => a,
            _ => return Err(format!("'intent_session.acc' must be an array of at most {MAX_IS_ACC} entries")),
        };
        let mut ids = std::collections::BTreeSet::new();
        for (i, e) in a.iter().enumerate() {
            let e = e.as_object().ok_or_else(|| format!("'intent_session.acc[{i}]' must be an object"))?;
            if let Some(k) = e.keys().find(|k| !["id", "post", "receipt"].contains(&k.as_str())) {
                return Err(format!("unknown field 'intent_session.acc[{i}].{k}'"));
            }
            let id = match s(e.get("id")) {
                Some(id) if is_ident(id) => id,
                _ => return Err(format!("'intent_session.acc[{i}].id' must match [A-Za-z0-9_]{{1,64}}")),
            };
            if !ids.insert(id) {
                return Err("'intent_session.acc' ids must be distinct".into());
            }
            if nonneg(e.get("post")).is_none() {
                return Err(format!("'intent_session.acc[{i}].post' must be a non-negative safe integer"));
            }
            if e.get("receipt").is_some() && !b32(e.get("receipt")) {
                return Err(format!("'intent_session.acc[{i}].receipt' is not canonical base64url (32 bytes)"));
            }
        }
    }
    if let Some(f) = o.get("facts") {
        digest_list(f, "facts", MAX_IS_FACTS)?;
    }
    if o.get("offer_set").is_some() && !b32(o.get("offer_set")) {
        return Err("'intent_session.offer_set' is not canonical base64url (32 bytes)".into());
    }
    if let Some(prov) = o.get("prov") {
        let p = match prov.as_object() {
            Some(p) if p.len() <= MAX_IS_PROV_PATHS => p,
            _ => return Err(format!("'intent_session.prov' must be an object of at most {MAX_IS_PROV_PATHS} entries")),
        };
        for (path, refs) in p {
            if !is_top_param_path(path) {
                return Err(format!("'intent_session.prov' key '{path}' is not action.params.<name>"));
            }
            let ok = refs.as_array().is_some_and(|r| !r.is_empty() && r.len() <= MAX_IS_PROV_REFS && r.iter().all(|x| bstr(Some(x), MAX_IS_STRING_BYTES)));
            if !ok {
                return Err(format!(
                    "'intent_session.prov.{path}' must be 1..{MAX_IS_PROV_REFS} non-empty strings of at most {MAX_IS_STRING_BYTES} UTF-8 bytes"
                ));
            }
        }
    }
    if let Some(c) = o.get("classes") {
        digest_list(c, "classes", MAX_IS_CLASSES)?;
    }
    if o.get("map_form").is_some_and(|m| m.as_str() != Some(MAP_FORM_COMMIT)) {
        return Err("'intent_session.map_form' must be \"commit\" when present".into());
    }
    if let Some(l) = o.get("labels") {
        digest_list(l, "labels", MAX_IS_LABELS)?;
    }
    Ok(())
}

/// `intentSessionCaveatError(c)`: exactly `{type: "intent_session", session, seq, root, prev?}`, `prev` present iff
/// `seq > 0`. `None` = well-formed.
pub fn intent_session_caveat_error(c: Option<&Value>) -> Option<String> {
    let c = match c.and_then(Value::as_object) {
        Some(c) if s(c.get("type")) == Some(INTENT_SESSION_CAVEAT) => c,
        _ => return Some("not an intent_session caveat".into()),
    };
    if let Some(k) = c.keys().find(|k| !["type", "session", "seq", "root", "prev"].contains(&k.as_str())) {
        return Some(format!("intent_session caveat: unknown member '{k}'"));
    }
    if !b32(c.get("session")) || !b32(c.get("root")) {
        return Some("intent_session caveat: session and root must be canonical base64url (32 bytes)".into());
    }
    let seq = match nonneg(c.get("seq")) {
        Some(q) if q <= MAX_SESSION_SEQ => q,
        _ => return Some("intent_session caveat: seq must be a safe integer in [0, 2147483647]".into()),
    };
    if (seq == 0) != c.get("prev").is_none() {
        return Some("intent_session caveat: prev is present exactly when seq > 0".into());
    }
    if c.get("prev").is_some() && !b32(c.get("prev")) {
        return Some("intent_session caveat: prev must be canonical base64url (32 bytes)".into());
    }
    None
}

/// `grantSessionCaveat(grant)`: the FIRST caveat of the grant that is an object with `type == "intent_session"`.
pub(crate) fn grant_session_caveat(grant: &Value) -> Option<&Value> {
    grant
        .get("caveats")?
        .as_array()?
        .iter()
        .find(|c| c.as_object().is_some_and(|o| s(o.get("type")) == Some(INTENT_SESSION_CAVEAT)))
}

/// `sessionRootShapeError(S)` of a signed root. `None` = well-formed.
pub fn session_root_shape_error(sv: &Value) -> Option<String> {
    let r = match sv.as_object() {
        Some(r) => r,
        None => return Some("session root is not an object".into()),
    };
    if let Some(k) = r.keys().find(|k| !ROOT_KEYS.contains(&k.as_str())) {
        return Some(format!("session root: unknown member '{k}'"));
    }
    if !same(r.get("v"), Some(&Value::from(1))) || s(r.get("kind")) != Some(INTENT_SESSION_KIND) {
        return Some("not a pca-intent-session v1".into());
    }
    if !b32(r.get("session")) || !b32(r.get("intent_ref")) {
        return Some("session and intent_ref must be canonical base64url (32 bytes)".into());
    }
    let principals = match r.get("principals").and_then(Value::as_array) {
        Some(p) if !p.is_empty() && p.len() <= MAX_SESSION_PRINCIPALS => p,
        _ => return Some(format!("principals must be 1..{MAX_SESSION_PRINCIPALS} keys")),
    };
    let mut keys = std::collections::BTreeSet::new();
    for p in principals {
        let p = match p.as_object() {
            Some(p) if p.keys().all(|k| ["key", "alg", "pq_pk"].contains(&k.as_str())) && b32(p.get("key")) => p,
            _ => return Some("principals entries are {key, alg?, pq_pk?} with a 32-byte key".into()),
        };
        if let Some(e) = optional_alg_error(p.get("alg")) {
            return Some(format!("principal alg: {e}"));
        }
        if p.get("pq_pk").is_some() && !b64any(p.get("pq_pk")) {
            return Some("principal pq_pk is not canonical base64url".into());
        }
        if !keys.insert(s(p.get("key")).unwrap_or("")) {
            return Some("principal keys must be distinct".into());
        }
    }
    let schema_ok = obj(r.get("schema")).is_some_and(|sc| exact_keys(sc, &["aud", "digest"]) && bstr_any(sc.get("aud")) && b32(sc.get("digest")));
    if !schema_ok {
        return Some("schema must be {aud, digest}".into());
    }
    let l = match obj(r.get("layers")) {
        Some(l) => l,
        None => return Some("layers must be an object".into()),
    };
    if let Some(k) = l.keys().find(|k| !["org", "std", "task"].contains(&k.as_str())) {
        return Some(format!("layers: unknown member '{k}'"));
    }
    let task_ok = obj(l.get("task")).is_some_and(|t| exact_keys(t, &["map_digest"]) && b32(t.get("map_digest")));
    if !task_ok {
        return Some("layers.task must be {map_digest}".into());
    }
    match l.get("org") {
        None => {}
        Some(o) => {
            if !o.as_object().is_some_and(|o| b32(o.get("digest"))) {
                return Some("layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)".into());
            }
        }
    }
    match l.get("std") {
        None => {}
        Some(d) => {
            let ok = d.as_object().is_some_and(|d| {
                exact_keys(d, &["digest", "profile", "version"])
                    && bstr(d.get("profile"), 128)
                    && sint(d.get("version")).is_some_and(|v| v >= 1)
                    && b32(d.get("digest"))
            });
            if !ok {
                return Some("layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)".into());
            }
        }
    }
    let accs = match r.get("accumulators").and_then(Value::as_array) {
        Some(a) if a.len() <= MAX_SESSION_ACCUMULATORS => a,
        _ => return Some(format!("accumulators must be an array of at most {MAX_SESSION_ACCUMULATORS}")),
    };
    let mut ids = std::collections::BTreeSet::new();
    for a in accs {
        if let Some(e) = accumulator_decl_error(a) {
            return Some(e);
        }
        if !ids.insert(s(a.get("id")).unwrap_or("")) {
            return Some("accumulator and monitor ids must be distinct".into());
        }
    }
    let mons = match r.get("monitors").and_then(Value::as_array) {
        Some(m) if m.len() <= MAX_SESSION_MONITORS => m,
        _ => return Some(format!("monitors must be an array of at most {MAX_SESSION_MONITORS}")),
    };
    let mut mids = std::collections::BTreeSet::new();
    for m in mons {
        if let Some(e) = monitor_decl_error(m) {
            return Some(e);
        }
        if !mids.insert(s(m.get("id")).unwrap_or("")) {
            return Some("monitor ids must be distinct".into());
        }
    }
    if !bstr(r.get("question_uri"), 2048) {
        return Some("question_uri must be a non-empty string".into());
    }
    if let Some(rv) = r.get("revocation") {
        let rv = match rv.as_object() {
            Some(x) if x.keys().all(|k| ["epoch_uri", "max_age_s", "key", "pq_pk"].contains(&k.as_str())) => x,
            _ => return Some("revocation must be {epoch_uri, max_age_s, key, pq_pk?}".into()),
        };
        if !bstr_any(rv.get("epoch_uri")) {
            return Some("revocation.epoch_uri must be a non-empty string".into());
        }
        if nonneg(rv.get("max_age_s")).is_none() {
            return Some("revocation.max_age_s must be a non-negative safe integer".into());
        }
        if !b32(rv.get("key")) {
            return Some("revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)".into());
        }
        if keys.contains(s(rv.get("key")).unwrap_or("")) {
            return Some("revocation.key must not be a session principal (a dedicated revocation authority)".into());
        }
        if rv.get("pq_pk").is_some() && !b64any(rv.get("pq_pk")) {
            return Some("revocation.pq_pk must be canonical base64url".into());
        }
    }
    if r.get("flows").is_some_and(|f| !f.is_object()) {
        return Some("flows must be an object".into());
    }
    if nonneg(r.get("expires_at")).is_none() {
        return Some("expires_at must be a non-negative safe integer (epoch ms)".into());
    }
    if !b32(r.get("signer")) {
        return Some("signer must be canonical base64url (32 bytes)".into());
    }
    if !keys.contains(s(r.get("signer")).unwrap_or("")) {
        return Some("signer is not one of the session principals".into());
    }
    if let Some(e) = suite_shape_error(r, "session root", "alg: ", "sig") {
        return Some(e);
    }
    if let Err(e) = super::canonicalize_strict(&Value::Object(root_body(r))) {
        return Some(format!("malformed session root: {e}"));
    }
    None
}

/// A non-empty string (no byte cap).
fn bstr_any(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(x)) if !x.is_empty())
}

/// `sessionRootBody(S)`: the signed body without `signer` and the suite / signature fields.
fn root_body(r: &Map<String, Value>) -> Map<String, Value> {
    let mut b = r.clone();
    for k in ["signer", "alg", "pq_pk", "sig", "pq_sig"] {
        b.remove(k);
    }
    b
}

/// `verifySessionRoot(S)` with NO verifier pins: an Ed25519 root verifies as before; a pure-PQ / hybrid root fails closed
/// (see [`verify_session_root_pinned`]).
pub fn verify_session_root(sv: &Value) -> Result<(), String> {
    verify_session_root_pinned(sv, None)
}

/// `verifySessionRoot(S, {pqPins})`: shape, signer listed, suite signature over
/// `"atlas-pca/intent-session/v1\0" || strictCanonical(body + signer + bound suite fields)`. R3-01 (fail closed): a
/// non-ed25519 root verifies only under the VERIFIER's pin for its signer (`pq_pins` = context `session.pq_pins`, an
/// object whose own member for the signer is a string), never under the root's own `principals[].pq_pk`; the signer's own
/// entry, when it declares a `pq_pk`, must agree. An Ed25519 root never consults the pins.
pub fn verify_session_root_pinned(sv: &Value, pq_pins: Option<&Value>) -> Result<(), String> {
    if let Some(e) = session_root_shape_error(sv) {
        return Err(e);
    }
    let r = sv.as_object().ok_or("session root is not an object")?;
    let signer = s(r.get("signer")).unwrap_or("");
    let principal = r
        .get("principals")
        .and_then(Value::as_array)
        .and_then(|ps| ps.iter().find(|p| s(p.get("key")) == Some(signer)))
        .ok_or("signer is not one of the session principals")?;
    let suite = suite_of(r.get("alg"))?;
    let pinned = pq_pins.and_then(Value::as_object).and_then(|m| m.get(signer)).filter(|v| v.is_string());
    let pin = if suite.needs_pq_pk {
        let Some(pv) = pinned else {
            return Err(format!(
                "session root suite '{}' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it",
                suite.alg
            ));
        };
        if r.get("pq_pk") != Some(pv) {
            return Err("session root pq_pk does not match the verifier's pin for the signer".into());
        }
        if principal.get("pq_pk").is_some_and(|e| Some(e) != r.get("pq_pk")) {
            return Err("session root pq_pk does not match the signer's principals entry".into());
        }
        Some((signer, pv))
    } else {
        None
    };
    let mut body = root_body(r);
    body.insert("signer".into(), Value::String(signer.into()));
    if !bind_suite_fields(&mut body, r.get("alg"), r.get("pq_pk"))? {
        return Err("session root signature invalid".into());
    }
    let msg = domain_message(INTENT_SESSION_SIG_DOMAIN, body).ok_or("malformed session root")?;
    if !verify_pinned_suite(r.get("alg"), signer, r.get("pq_pk"), &msg, r.get("sig"), r.get("pq_sig"), pin)? {
        return Err("session root signature invalid".into());
    }
    Ok(())
}

/// `sessionRootDigest(S)` = b64u(sha256(strictCanonical({d: "atlas-pca/intent-session-ref/v1", s: S}))).
pub fn session_root_digest(sv: &Value) -> Option<String> {
    let mut m = Map::new();
    m.insert("d".into(), Value::String(INTENT_SESSION_REF_DOMAIN.into()));
    m.insert("s".into(), sv.clone());
    digest_of(&Value::Object(m))
}

#[cfg(test)]
#[path = "k042_intent_session_test.rs"]
mod k042_test;
