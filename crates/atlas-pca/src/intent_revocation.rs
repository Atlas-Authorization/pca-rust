//! Session revocation (Intent Layer v2 rule 13 step 7, T22): the signed revocation epoch (`revocation.ts`
//! `checkRevocationEpoch`), its FULL revoked list (the revocation-set root) and the append-only rule against the last
//! epoch a verifier accepted (`intent-revocation.ts` `checkSessionRevocation`).

use serde_json::{Map, Value};

use super::intent_strict::*;
use super::intent_suite::{bind_suite_fields, domain_message, suite_of, verify_pinned_suite};
use super::{b64_encode, canonicalize_strict, merkle_root, sha};

const REVEPOCH_DOMAIN: &str = "atlas-pca/revepoch/v1\0";
const EPOCH_SKEW_MS: f64 = 60_000.0;

/// `"pca-intent:session:" + session`.
pub fn session_revocation_id(session: &str) -> String {
    format!("pca-intent:session:{session}")
}
/// `"pca-intent:map:" + map_digest`.
pub fn map_revocation_id(map_digest: &str) -> String {
    format!("pca-intent:map:{map_digest}")
}
/// `"pca-intent:delta:" + grant id`.
pub fn delta_revocation_id(grant_id: &str) -> String {
    format!("pca-intent:delta:{grant_id}")
}
/// `"pca-intent:profile:" + profile + "@" + version`.
pub fn profile_revocation_id(profile: &str, version: &str) -> String {
    format!("pca-intent:profile:{profile}@{version}")
}
/// The `grant_ref` of a session revocation epoch: `"pca-intent-session:" + session`.
pub fn session_revocation_scope(session: &str) -> String {
    format!("pca-intent-session:{session}")
}


/// A non-negative safe integer read as a double (never `-0`).
fn nonneg_safe(x: f64) -> bool {
    safe_integer_f64(x) && x >= 0.0 && !(x == 0.0 && x.is_sign_negative())
}

/// `revset_root(L)` = b64u(sha256("pca-revset/v1\0" || strictCanonical({size: |L|, tree}))), `tree` the RFC-6962-shaped
/// Merkle root over the ids in order (leaf `SHA-256(0x00 || canonical(id))`), b64u(sha256("")) for the empty list.
pub fn revset_root(list: &[String]) -> Option<String> {
    let tree = if list.is_empty() {
        b64_encode(&sha(b""))
    } else {
        let leaves: Vec<Value> = list.iter().cloned().map(Value::String).collect();
        merkle_root(&leaves).ok()?
    };
    let mut m = Map::new();
    m.insert("size".into(), Value::from(list.len()));
    m.insert("tree".into(), Value::String(tree));
    let c = canonicalize_strict(&Value::Object(m)).ok()?;
    let mut b = b"pca-revset/v1\0".to_vec();
    b.extend_from_slice(c.as_bytes());
    Some(b64_encode(&sha(&b)))
}

/// Strict shape of a revocation epoch as rule 13 consumes it (`revocationEpochShapeError`): every number a non-negative
/// safe integer, every string a string, an optional member absent or of its type (`null` is malformed), and the `alg` a
/// suite the dispatch implements (`unsupported_suite` otherwise).
pub fn revocation_epoch_shape_error(ep: &Value) -> Option<String> {
    let o = match ep.as_object() {
        Some(o) => o,
        None => return Some("the revocation epoch must be an object".into()),
    };
    for k in ["instance_id", "grant_ref", "root", "guardian", "sig"] {
        if !o.get(k).is_some_and(Value::is_string) {
            return Some(format!("revocation epoch {k} must be a string"));
        }
    }
    for k in ["epoch", "set_size", "issued_at", "not_after"] {
        if nonneg(o.get(k)).is_none() {
            return Some(format!("revocation epoch {k} must be a non-negative safe integer"));
        }
    }
    if o.get("guardian_epoch").is_some() && nonneg(o.get("guardian_epoch")).is_none() {
        return Some("revocation epoch guardian_epoch must be a non-negative safe integer".into());
    }
    if let Err(e) = suite_of(o.get("alg")) {
        return Some(format!("revocation epoch alg: {e}"));
    }
    for k in ["pq_pk", "pq_sig"] {
        if o.get(k).is_some_and(|v| !v.is_string()) {
            return Some(format!("revocation epoch {k} must be a string"));
        }
    }
    None
}

/// `checkRevocationEpoch(ep, {guardianPublic, now, grantRef, pqPins})` on a shape-checked epoch: the signature through
/// the suite dispatch, a PQ suite only under the PQ key PINNED for the guardian; then scope, `now <= not_after` and
/// `issued_at <= now + 60 s`.
fn check_revocation_epoch(o: &Map<String, Value>, guardian: &str, now: f64, grant_ref: &str, pin: Option<(&str, &Value)>) -> Result<(), String> {
    if s(o.get("guardian")) != Some(guardian) {
        return Err("revocation epoch not signed by the pinned guardian".into());
    }
    let mut body = Map::new();
    for f in ["instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"] {
        body.insert(f.into(), o.get(f).cloned().unwrap_or(Value::Null));
    }
    if !bind_suite_fields(&mut body, o.get("alg"), o.get("pq_pk"))? {
        return Err("revocation epoch signature invalid".into());
    }
    let msg = domain_message(REVEPOCH_DOMAIN, body).ok_or("revocation epoch check error")?;
    if !verify_pinned_suite(o.get("alg"), guardian, o.get("pq_pk"), &msg, o.get("sig"), o.get("pq_sig"), pin)? {
        return Err("revocation epoch signature invalid".into());
    }
    if s(o.get("grant_ref")) != Some(grant_ref) {
        return Err("revocation epoch is for a different grant".into());
    }
    if !(now <= num(o.get("not_after")).unwrap_or(f64::NAN)) {
        return Err("revocation epoch expired (stale revocation root)".into());
    }
    if !(num(o.get("issued_at")).unwrap_or(f64::NAN) <= now + EPOCH_SKEW_MS) {
        return Err("revocation epoch issued in the future".into());
    }
    Ok(())
}

/// `revokedListError(ev)`: `revoked` is the FULL signed set: an array of strings strictly ascending by UTF-8 bytes,
/// `revoked.length == set_size == epoch` and `revset_root(revoked) == root`. On success the list.
fn revoked_list(epoch: &Map<String, Value>, revoked: Option<&Value>) -> Result<Vec<String>, String> {
    let r = revoked.and_then(Value::as_array).ok_or("revoked must be an array of ids")?;
    let mut list = Vec::with_capacity(r.len());
    for x in r {
        list.push(x.as_str().ok_or("revoked must be an array of ids")?.to_string());
    }
    if !list.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()) {
        return Err("revoked must be sorted by UTF-8 bytes and distinct".into());
    }
    let size = nonneg(epoch.get("set_size"));
    if size != Some(list.len() as i64) || nonneg(epoch.get("epoch")) != size {
        return Err("the epoch must be numbered by its set size and list exactly set_size ids".into());
    }
    if revset_root(&list).as_deref() != s(epoch.get("root")) {
        return Err("the revoked list is not the signed set (root mismatch)".into());
    }
    Ok(list)
}

/// `checkSessionRevocation({epoch, revoked}, {session, authority, ids, now, maxAgeMs, pin, scope?, last?})` (NORMATIVE,
/// rule 13 step 7), first failure wins:
/// a. the max age a non-negative safe integer, the clock a safe integer;
/// b. the evidence an object, the epoch strictly shaped, `epoch.guardian == authority` (only the dedicated authority);
/// c. the epoch verifies under the authority (a PQ suite only under `authority_pq_pk`), scope, `now <= not_after`,
///    `issued_at <= now + 60 s`;
/// d. `now - issued_at <= max_age_ms`;
/// e. `revoked` is the full signed set ([`revset_root`]);
/// f. append-only against `last` (well-formed by b's shape and e): no rollback, no dropped id, no equivocation;
/// g. no id of `ids` is revoked.
#[allow(clippy::too_many_arguments)]
pub fn check_session_revocation(
    evidence: Option<&Value>,
    session: &str,
    authority: &str,
    ids: &[String],
    now: f64,
    max_age_ms: f64,
    scope: Option<&str>,
    authority_pq_pk: Option<&Value>,
    last: Option<&Value>,
) -> Result<(), String> {
    if !nonneg_safe(max_age_ms) {
        return Err("revocation max age misconfigured (fail closed)".into());
    }
    if !safe_integer_f64(now) || (now == 0.0 && now.is_sign_negative()) {
        return Err("the verifier clock is not a safe integer (fail closed)".into());
    }
    let ev = evidence.and_then(Value::as_object).ok_or("no session revocation epoch supplied")?;
    if let Some(k) = ev.keys().find(|k| *k != "epoch" && *k != "revoked") {
        return Err(format!("the revocation evidence has the unknown member '{k}' (it is exactly {{epoch, revoked}})"));
    }
    let ep = ev.get("epoch").unwrap_or(&Value::Null);
    if let Some(e) = revocation_epoch_shape_error(ep) {
        return Err(e);
    }
    let o = ep.as_object().ok_or("the revocation epoch must be an object")?;
    if s(o.get("guardian")) != Some(authority) {
        return Err("the revocation epoch is not signed by the session revocation authority".into());
    }
    let pin = authority_pq_pk.map(|p| (authority, p));
    let default_scope = session_revocation_scope(session);
    check_revocation_epoch(o, authority, now, scope.unwrap_or(&default_scope), pin)?;
    let issued = num(o.get("issued_at")).unwrap_or(f64::NAN);
    if !(now - issued <= max_age_ms) {
        return Err(format!("the session revocation epoch is older than {max_age_ms} ms"));
    }
    let revoked = revoked_list(o, ev.get("revoked"))?;
    if let Some(last) = last {
        let malformed = || "the tracked last epoch is malformed (fail closed)".to_string();
        let lo = last.as_object().filter(|lo| lo.keys().all(|k| k == "epoch" || k == "revoked")).ok_or_else(malformed)?;
        let le = lo.get("epoch").unwrap_or(&Value::Null);
        if revocation_epoch_shape_error(le).is_some() {
            return Err(malformed());
        }
        let le = le.as_object().ok_or_else(malformed)?;
        let last_list = revoked_list(le, lo.get("revoked")).map_err(|_| malformed())?;
        let (e_now, e_last) = (nonneg(o.get("epoch")).unwrap_or(-1), nonneg(le.get("epoch")).unwrap_or(-1));
        if e_now < e_last {
            return Err("revocation epoch rollback (older than the last accepted)".into());
        }
        if let Some(id) = last_list.iter().find(|id| revoked.binary_search_by(|x| x.as_bytes().cmp(id.as_bytes())).is_err()) {
            return Err(format!("the epoch drops '{id}', revoked in the last accepted epoch (not append-only)"));
        }
        if e_now == e_last && s(o.get("root")) != s(le.get("root")) {
            return Err("two different revocation sets under one epoch number (equivocation)".into());
        }
    }
    if let Some(id) = ids.iter().find(|id| revoked.binary_search_by(|x| x.as_bytes().cmp(id.as_bytes())).is_ok()) {
        return Err(format!("'{id}' is revoked"));
    }
    Ok(())
}
