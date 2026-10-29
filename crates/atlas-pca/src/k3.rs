//! Operational-plane artifacts, verify-only: signed policy bundles, decision-log records / heads / inclusion / batches,
//! list-authorized receipts and cursors, and grant-management signatures (amend, revoke, need approval).
//!
//! Every signature is Ed25519 (strict) over `domain || strictCanonical(body)`. Every function is total: malformed input
//! returns the failure value, never a panic. Verdicts are returned in the language-neutral conformance shape
//! (`{ok, code, reason}` ...) so the shared vectors compare byte for byte.
use crate::fresh_at::verify_body;
use crate::{decode_b64u_strict, hash_canonical_strict, safe_int, verify_inclusion};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const BUNDLE_REF_DOMAIN: &str = "atlas-pca/policy-bundle-ref/v1";
pub const BUNDLE_DOMAIN: &str = "atlas-pca/policy-bundle/v1\0";
pub const RECORD_DOMAIN: &str = "atlas-pca/decision-record/v1";
pub const LOG_HEAD_DOMAIN: &str = "atlas-pca/decision-log-head/v1\0";
pub const LIST_RECEIPT_DOMAIN: &str = "atlas-pca/list-receipt/v1\0";
pub const LIST_CURSOR_DOMAIN: &str = "atlas-pca/list-cursor/v1\0";
pub const GRANT_AMEND_DOMAIN: &str = "atlas-pca/grant-amend/v1\0";
pub const GRANT_REVOKE_DOMAIN: &str = "atlas-pca/grant-revoke/v1\0";
pub const NEED_APPROVE_DOMAIN: &str = "atlas-pca/need-approve/v1\0";

const MAX_LIST: usize = 4096;

// ---- helpers ------------------------------------------------------------------------------------------------------------

fn nat(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|n| *n >= 0)
}

/// A non-empty string of at most `max` UTF-16 code units.
fn is_str(v: Option<&Value>, max: usize) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.encode_utf16().count() <= max)
}

fn str_of<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// `o` without the member `k` (the signed body of an artifact that carries its own signature).
fn without(o: &Map<String, Value>, k: &str) -> Value {
    let mut m = o.clone();
    m.remove(k);
    Value::Object(m)
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

fn fail_code(code: &str) -> Value {
    json!({"ok": false, "code": code})
}

// ---- policy bundles -----------------------------------------------------------------------------------------------------

/// Digest of a bundle (its signatures excluded); `None` for a non-object or a value outside the strict JSON profile.
pub fn bundle_digest(b: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": BUNDLE_REF_DOMAIN, "b": without(b.as_object()?, "sigs")}))
}

/// Dotted numeric version comparison (-1, 0, 1); a non-numeric part compares as the reference's `NaN` (1).
pub fn compare_version(a: &str, b: &str) -> i32 {
    let num = |s: Option<&str>| -> f64 {
        match s.map(str::trim) {
            None | Some("") => 0.0,
            Some(t) => t.parse::<f64>().unwrap_or(f64::NAN),
        }
    };
    let pa: Vec<&str> = a.split('.').collect();
    let pb: Vec<&str> = b.split('.').collect();
    for i in 0..pa.len().max(pb.len()) {
        let d = num(pa.get(i).copied()) - num(pb.get(i).copied());
        if d != 0.0 {
            return if d < 0.0 { -1 } else { 1 };
        }
    }
    0
}

fn version_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    (1..=4).contains(&parts.len())
        && parts
            .iter()
            .all(|p| (1..=6).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit()))
}

/// Why `b` is not a well-formed policy bundle, or `None`.
pub fn bundle_shape_error(b: &Value) -> Option<String> {
    let o = match b.as_object() {
        Some(o) => o,
        None => return Some("not a policy bundle".into()),
    };
    if o.get("v").and_then(safe_int) != Some(1)
        || o.get("kind").and_then(Value::as_str) != Some("pca-policy-bundle")
    {
        return Some("not a policy bundle".into());
    }
    let revision = nat(o.get("revision"));
    if !matches!(revision, Some(r) if r >= 1) || nat(o.get("issued_at")).is_none() {
        return Some("bad revision or time".into());
    }
    let prev_ok = if revision == Some(1) {
        o.get("prev").is_none()
    } else {
        is_str(o.get("prev"), 128)
    };
    if !prev_ok {
        return Some("prev must be absent at revision 1 and present after".into());
    }
    for (k, label) in [
        ("grants", "bad grants"),
        ("template_digests", "bad template_digests"),
    ] {
        match o.get(k).and_then(Value::as_array) {
            Some(a) if a.len() <= MAX_LIST && a.iter().all(|g| is_str(Some(g), 128)) => {}
            _ => return Some(label.into()),
        }
    }
    for k in ["schema_digest", "constitution_digest", "flow_rules_digest"] {
        if o.get(k).is_some() && !is_str(o.get(k), 128) {
            return Some(format!("bad {k}"));
        }
    }
    if !o
        .get("min_verifier_version")
        .and_then(Value::as_str)
        .is_some_and(version_ok)
    {
        return Some("bad min_verifier_version".into());
    }
    None
}

fn bundle_fail(code: &str, reason: String) -> Value {
    json!({"ok": false, "code": code, "reason": reason})
}

/// Verify a signed bundle: `signers` is the pinned set (signatures by anyone else are ignored), `threshold` the number of
/// distinct valid pinned signatures needed, `verifier_version` this verifier's own version (against `min_verifier_version`),
/// `last` the newest accepted `(revision, digest)` (a lower revision is a rollback; the next one must chain by `prev`).
/// Returns `{ok:true, revision, digest, signers}` or `{ok:false, code, reason}`.
pub fn verify_bundle(
    b: &Value,
    signers: &[&str],
    threshold: i64,
    verifier_version: &str,
    last: Option<(i64, &str)>,
) -> Value {
    if let Some(e) = bundle_shape_error(b) {
        return bundle_fail("malformed", e);
    }
    let o = match b.as_object() {
        Some(o) => o,
        None => return bundle_fail("malformed", "not a policy bundle".into()),
    };
    let sigs = match o.get("sigs").and_then(Value::as_array) {
        Some(s) if s.len() <= 64 && threshold >= 1 => s,
        _ => return bundle_fail("malformed", "bad sigs or threshold".into()),
    };
    let body = without(o, "sigs");
    let mut good: Vec<&str> = Vec::new();
    for s in sigs {
        if let Some(who) = s.as_object().and_then(|_| str_of(s, "signer")) {
            if signers.contains(&who)
                && !good.contains(&who)
                && verify_body(BUNDLE_DOMAIN, &body, who, str_of(s, "sig"))
            {
                good.push(who);
            }
        }
    }
    if (good.len() as i64) < threshold {
        return bundle_fail(
            "below_threshold",
            format!(
                "{} valid pinned signature(s), need {}",
                good.len(),
                threshold
            ),
        );
    }
    let min = str_of(b, "min_verifier_version").unwrap_or("");
    if !version_ok(verifier_version) || compare_version(verifier_version, min) < 0 {
        return bundle_fail("verifier_too_old", format!("needs verifier >= {min}"));
    }
    let revision = nat(o.get("revision")).unwrap_or(0);
    let digest = match bundle_digest(b) {
        Some(d) => d,
        None => {
            return bundle_fail(
                "malformed",
                "bundle is outside the strict JSON profile".into(),
            )
        }
    };
    if let Some((l_rev, l_digest)) = last {
        if revision < l_rev {
            return bundle_fail(
                "rollback",
                format!("revision {revision} < accepted {l_rev}"),
            );
        }
        if revision == l_rev && digest != l_digest {
            return bundle_fail("broken_chain", "same revision, different content".into());
        }
        if revision == l_rev + 1 && str_of(b, "prev") != Some(l_digest) {
            return bundle_fail(
                "broken_chain",
                "prev does not chain to the accepted revision".into(),
            );
        }
    }
    json!({"ok": true, "revision": revision, "digest": digest, "signers": good})
}

// ---- decision records, heads, batches -----------------------------------------------------------------------------------

/// Commit of a decision record (what the log's Merkle tree and hash chain are over); `None` outside the strict profile.
pub fn record_commit(r: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": RECORD_DOMAIN, "r": r}))
}

/// A well-formed log head signed by `signer` over exactly its content.
pub fn verify_log_head(h: &Value, signer: &str) -> bool {
    let o = match h.as_object() {
        Some(o) => o,
        None => return false,
    };
    o.get("v").and_then(safe_int) == Some(1)
        && str_of(h, "signer") == Some(signer)
        && nat(o.get("size")).is_some()
        && nat(o.get("issued_at")).is_some()
        && str_of(h, "root").is_some()
        && str_of(h, "last_commit").is_some()
        && verify_body(
            LOG_HEAD_DOMAIN,
            &without(o, "sig"),
            signer,
            str_of(h, "sig"),
        )
}

/// Offline: `rec` is in the log the signed `head` commits to (RFC 6962 inclusion of its commit string), and the head is by `signer`.
pub fn verify_record_inclusion(rec: &Value, proof: &Value, head: &Value, signer: &str) -> bool {
    if !verify_log_head(head, signer) {
        return false;
    }
    match (record_commit(rec), str_of(head, "root")) {
        (Some(commit), Some(root)) => {
            verify_inclusion(root, proof.as_object(), &Value::String(commit))
        }
        _ => false,
    }
}

fn batch_fail(reason: &str) -> Value {
    json!({"ok": false, "reason": reason})
}

/// Receiver side of the decision stream: contiguous sequence, intact hash chain from the receiver's state
/// (`next`, `last_commit`), and (when the batch reaches the head) the head's last commit and size match.
/// Returns `{ok:true, next, lastCommit}` or `{ok:false, reason}`.
pub fn verify_batch(batch: &Value, next: i64, last_commit: &str, signer: &str) -> Value {
    let (from, records, head) = match (
        batch.get("from").and_then(safe_int),
        batch.get("records").and_then(Value::as_array),
        batch.get("head"),
    ) {
        (Some(f), Some(r), Some(h)) => (f, r, h),
        _ => return batch_fail("malformed batch"),
    };
    if from != next {
        return batch_fail(&format!(
            "gap or replay: batch starts at {from}, expected {next}"
        ));
    }
    if !verify_log_head(head, signer) {
        return batch_fail("head not signed by the pinned log signer");
    }
    let mut last = last_commit.to_string();
    let mut n = next;
    for r in records {
        if !r.is_object() {
            return batch_fail("malformed batch");
        }
        if r.get("seq").and_then(safe_int) != Some(n) || str_of(r, "prev") != Some(last.as_str()) {
            let seq = match r.get("seq") {
                Some(Value::Number(x)) => x.to_string(),
                Some(other) => crate::canonicalize(other),
                None => "undefined".to_string(),
            };
            return batch_fail(&format!("chain broken at seq {seq}"));
        }
        last = match record_commit(r) {
            Some(c) => c,
            None => return batch_fail("malformed batch"),
        };
        n += 1;
    }
    let size = nat(head.get("size")).unwrap_or(0);
    if n > size {
        return batch_fail("batch is longer than the signed head");
    }
    if n == size && str_of(head, "last_commit") != Some(last.as_str()) {
        return batch_fail("batch end does not match the signed head");
    }
    json!({"ok": true, "next": n, "lastCommit": last})
}

// ---- list-authorized ----------------------------------------------------------------------------------------------------

/// Digest of the returned object ids, in order (`objects` is an array of strings).
pub fn objects_digest(objects: &Value) -> Option<String> {
    hash_canonical_strict(&json!({"d": "atlas-pca/list-objects/v1", "o": objects}))
}

/// A well-formed list receipt signed by `signer`; with `objects`, also that they are exactly the objects it counted and digested.
pub fn verify_list_receipt(r: &Value, signer: &str, objects: Option<&Value>) -> bool {
    let o = match r.as_object() {
        Some(o) => o,
        None => return false,
    };
    if o.get("v").and_then(safe_int) != Some(1)
        || str_of(r, "signer") != Some(signer)
        || !is_str(o.get("subject"), 512)
        || !is_str(o.get("resource_type"), 512)
        || nat(o.get("count")).is_none()
        || nat(o.get("issued_at")).is_none()
        || !verify_body(
            LIST_RECEIPT_DOMAIN,
            &without(o, "sig"),
            signer,
            str_of(r, "sig"),
        )
    {
        return false;
    }
    match objects {
        None => true,
        Some(objs) => {
            objs.as_array().map(Vec::len).map(|n| n as i64) == nat(o.get("count"))
                && objects_digest(objs).as_deref() == str_of(r, "objects_digest")
        }
    }
}

/// What a page cursor is bound to: `{subject, resourceType, filterId, policyDigest, limit, relation?:{relation}}`.
pub fn list_bind(a: &Value) -> Option<String> {
    let relation = a
        .get("relation")
        .and_then(|r| r.get("relation"))
        .cloned()
        .unwrap_or(Value::Null);
    hash_canonical_strict(&json!({
        "s": a.get("subject")?, "t": a.get("resourceType")?, "f": a.get("filterId")?, "p": a.get("policyDigest")?,
        "r": relation, "l": a.get("limit")?,
    }))
}

/// Verify a page cursor: shape, signature by `signer`, and (with `bind`) that it was issued for exactly those inputs.
/// Returns `{ok:true, inner?, skip}` or `{ok:false, reason: "malformed" | "signature" | "bind"}`.
pub fn verify_list_cursor(tok: &Value, signer: &str, bind: Option<&Value>) -> Value {
    let bad = |why: &str| json!({"ok": false, "reason": why});
    let tok = match tok.as_str() {
        Some(t) => t,
        None => return bad("malformed"),
    };
    let mut parts = tok.split('.');
    let (p, s, extra) = (parts.next().unwrap_or(""), parts.next(), parts.next());
    let c: Value = match decode_b64u_strict(p, None)
        .filter(|raw| !raw.is_empty())
        .and_then(|raw| serde_json::from_str(&String::from_utf8_lossy(&raw)).ok())
    {
        Some(c) => c,
        None => return bad("malformed"),
    };
    let s = match s {
        Some(s) if !s.is_empty() && extra.is_none() => s,
        _ => return bad("malformed"),
    };
    let o = match c.as_object() {
        Some(o) => o,
        None => return bad("malformed"),
    };
    if o.get("v").and_then(safe_int) != Some(1)
        || str_of(&c, "bind").is_none()
        || nat(o.get("skip")).is_none()
        || o.get("inner").is_some_and(|i| !i.is_string())
    {
        return bad("malformed");
    }
    if str_of(&c, "signer") != Some(signer) || !verify_body(LIST_CURSOR_DOMAIN, &c, signer, Some(s))
    {
        return bad("signature");
    }
    if let Some(b) = bind {
        if list_bind(b).as_deref() != str_of(&c, "bind") {
            return bad("bind");
        }
    }
    let mut out = json!({"ok": true, "skip": nat(o.get("skip"))});
    if let Some(inner) = o.get("inner") {
        out["inner"] = inner.clone();
    }
    out
}

// ---- grant authority ----------------------------------------------------------------------------------------------------

/// The comparable shape of a grant's authority.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Authority {
    pub verbs: Vec<String>,
    /// Exact resource ids, or a prefix ending in `*`.
    pub resources: Vec<String>,
    /// Named numeric ceilings; a lower ceiling is narrower. A ceiling absent from the old authority is unbounded there.
    pub limits: BTreeMap<String, f64>,
    /// Epoch ms; a sooner expiry is narrower. `None` never expires.
    pub expires_at: Option<f64>,
}

fn string_list(v: Option<&Value>, max_len: usize, max_str: usize) -> Option<Vec<String>> {
    let a = v?.as_array()?;
    if a.len() > max_len || !a.iter().all(|x| is_str(Some(x), max_str)) {
        return None;
    }
    Some(
        a.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
    )
}

fn limits_of(v: &Value) -> Option<BTreeMap<String, f64>> {
    v.as_object()?
        .iter()
        .map(|(k, x)| {
            Some((
                k.clone(),
                x.as_f64().filter(|f| f.is_finite() && *f >= 0.0)?,
            ))
        })
        .collect()
}

impl Authority {
    /// Parse and validate (`None` when malformed: lists and strings within bounds, finite non-negative ceilings, safe-integer expiry).
    pub fn from_json(v: &Value) -> Option<Self> {
        v.as_object()?;
        let limits = match v.get("limits") {
            None => BTreeMap::new(),
            Some(l) => limits_of(l)?,
        };
        let expires_at = match v.get("expires_at") {
            None => None,
            Some(e) => Some(safe_int(e).filter(|n| *n >= 0)? as f64),
        };
        Some(Self {
            verbs: string_list(v.get("verbs"), 256, 128)?,
            resources: string_list(v.get("resources"), 1024, 512)?,
            limits,
            expires_at,
        })
    }

    /// Back to JSON (`limits` only when non-empty).
    pub fn to_json(&self) -> Value {
        let num = |f: f64| {
            if f.fract() == 0.0 && f.abs() < 9.0e15 {
                Value::from(f as i64)
            } else {
                Value::from(f)
            }
        };
        let mut m = Map::new();
        m.insert("verbs".into(), json!(self.verbs));
        m.insert("resources".into(), json!(self.resources));
        if !self.limits.is_empty() {
            m.insert(
                "limits".into(),
                Value::Object(
                    self.limits
                        .iter()
                        .map(|(k, v)| (k.clone(), num(*v)))
                        .collect(),
                ),
            );
        }
        if let Some(e) = self.expires_at {
            m.insert("expires_at".into(), num(e));
        }
        Value::Object(m)
    }
}

fn res_covers(p: &str, r: &str) -> bool {
    match p.strip_suffix('*') {
        Some(prefix) => r.starts_with(prefix),
        None => p == r,
    }
}

fn res_subset(small: &[String], big: &[String]) -> bool {
    small.iter().all(|s| {
        big.iter()
            .any(|b| res_covers(b, s) && (!s.ends_with('*') || b.ends_with('*') || b == s))
    })
}

/// Everything `a` allows, `b` allows.
fn authority_le(a: &Authority, b: &Authority) -> bool {
    if !a.verbs.iter().all(|v| b.verbs.contains(v)) || !res_subset(&a.resources, &b.resources) {
        return false;
    }
    for (k, v) in &a.limits {
        if let Some(bv) = b.limits.get(k) {
            if v > bv {
                return false;
            }
        }
    }
    if b.limits.keys().any(|k| !a.limits.contains_key(k)) {
        return false;
    }
    a.expires_at.unwrap_or(f64::INFINITY) <= b.expires_at.unwrap_or(f64::INFINITY)
}

/// `narrower` | `equal` | `wider` | `incomparable` (an incomparable change is treated as wider by callers).
pub fn compare_authority_parsed(old: &Authority, new: &Authority) -> &'static str {
    match (authority_le(new, old), authority_le(old, new)) {
        (true, true) => "equal",
        (true, false) => "narrower",
        (false, true) => "wider",
        _ => "incomparable",
    }
}

/// [`compare_authority_parsed`] on JSON authorities; a malformed one is `incomparable` (fail closed).
pub fn compare_authority(old: &Value, new: &Value) -> &'static str {
    match (Authority::from_json(old), Authority::from_json(new)) {
        (Some(o), Some(n)) => compare_authority_parsed(&o, &n),
        _ => "incomparable",
    }
}

/// Content address of an authority (verbs and resources sorted, so their order does not matter).
pub fn authority_digest(a: &Value) -> Option<String> {
    let mut m = a.as_object()?.clone();
    for k in ["verbs", "resources"] {
        let mut items = m.get(k)?.as_array()?.clone();
        items.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
        m.insert(k.into(), Value::Array(items));
    }
    hash_canonical_strict(&json!({"d": "atlas-pca/authority/v1", "a": Value::Object(m)}))
}

fn union(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = a.to_vec();
    for x in b {
        if !out.contains(x) {
            out.push(x.clone());
        }
    }
    out
}

/// Union of verbs and resources; a ceiling or expiry is only ever RAISED by the delta (one the delta omits is kept).
pub fn merge_authority(a: &Authority, d: &Authority) -> Authority {
    Authority {
        verbs: union(&a.verbs, &d.verbs),
        resources: union(&a.resources, &d.resources),
        limits: a
            .limits
            .iter()
            .map(|(k, v)| (k.clone(), v.max(d.limits.get(k).copied().unwrap_or(*v))))
            .collect(),
        expires_at: a.expires_at.map(|e| e.max(d.expires_at.unwrap_or(e))),
    }
}

// ---- grant management ---------------------------------------------------------------------------------------------------

/// Decide an amendment against the current grant facts `{id, rev, principal, agent, status, authority}`. Check order is
/// normative: request shape, authority shape, grant active, classification (`narrow` that changes nothing or widens is
/// `not_narrower`), signature (`signature_required`, then `bad_signature`; widening needs the PRINCIPAL), step-up for a
/// widening (`step_up_ok` is the already-evaluated verdict). Returns `{ok:true, widens, next_digest}` or `{ok:false, code}`.
pub fn verify_amendment(cur: &Value, req: &Value, step_up_ok: bool) -> Value {
    let action = match req.get("action").and_then(Value::as_str) {
        Some(a @ ("narrow" | "merge" | "replace")) if req.is_object() => a,
        _ => return fail_code("bad_request"),
    };
    let req_authority = match req.get("authority").and_then(Authority::from_json) {
        Some(a) => a,
        None => return fail_code("bad_request"),
    };
    if str_of(cur, "status") != Some("active") {
        return fail_code("not_active");
    }
    let cur_authority = match cur.get("authority").and_then(Authority::from_json) {
        Some(a) => a,
        None => return fail_code("bad_request"),
    };
    let next = if action == "merge" {
        merge_authority(&cur_authority, &req_authority)
    } else {
        req_authority
    };
    let order = compare_authority_parsed(&cur_authority, &next);
    let widens = order == "wider" || order == "incomparable";
    if action == "narrow" && (widens || order == "equal") {
        return fail_code("not_narrower");
    }
    let signed_by = str_of(req, "signed_by").filter(|s| *s == "holder" || *s == "principal");
    let sig = req.get("sig").and_then(Value::as_str);
    let signed_by = match (sig, signed_by) {
        (Some(_), Some(who)) if !(widens && who != "principal") => who,
        _ => return fail_code("signature_required"),
    };
    let signer = str_of(
        cur,
        if signed_by == "principal" {
            "principal"
        } else {
            "agent"
        },
    )
    .unwrap_or("");
    let msg = match req.get("authority").and_then(authority_digest) {
        Some(d) => {
            json!({"grant": cur.get("id").cloned().unwrap_or(Value::Null), "rev": cur.get("rev").cloned().unwrap_or(Value::Null), "action": action, "authority": d})
        }
        None => return fail_code("bad_signature"),
    };
    if !verify_body(GRANT_AMEND_DOMAIN, &msg, signer, sig) {
        return fail_code("bad_signature");
    }
    if widens && !step_up_ok {
        return fail_code("step_up_required");
    }
    // the next authority: the request's own JSON when it replaces, the merged one when it merges
    let next_json = if action == "merge" {
        next.to_json()
    } else {
        req.get("authority").cloned().unwrap_or(Value::Null)
    };
    match authority_digest(&next_json) {
        Some(d) => json!({"ok": true, "widens": widens, "next_digest": d}),
        None => fail_code("bad_request"),
    }
}

/// Decide a revocation's authority: the principal's signature over `{grant: root.id, scope}`. `root` is `{id, principal}`.
/// Returns `{ok:true, scope}` or `{ok:false, code}`.
pub fn verify_revoke_signature(root: &Value, scope: &Value, sig: Option<&Value>) -> Value {
    let scope = match scope.as_str() {
        Some(s @ ("grant" | "agent" | "subtree")) => s,
        _ => return fail_code("bad_request"),
    };
    let msg = json!({"grant": root.get("id").cloned().unwrap_or(Value::Null), "scope": scope});
    if !verify_body(
        GRANT_REVOKE_DOMAIN,
        &msg,
        str_of(root, "principal").unwrap_or(""),
        sig.and_then(Value::as_str),
    ) {
        return fail_code("bad_signature");
    }
    json!({"ok": true, "scope": scope})
}

/// Decide a needs approval: principal signature over `{need, grant, rev, approved}`, same count, each approved need names
/// the same verb and resource with amounts only LOWERED and only when `adjustable`, then step-up. `nr` is
/// `{id, grant_id, needs, status}`, `g` the grant facts. Returns `{ok:true, authority_digest}` (of the merged authority)
/// or `{ok:false, code}`.
pub fn verify_need_approval(
    nr: &Value,
    g: &Value,
    approved: &Value,
    sig: Option<&Value>,
    step_up_ok: bool,
) -> Value {
    const LOWER_ONLY: &str = "need_not_lowered_only";
    if str_of(nr, "status") != Some("pending") {
        return fail_code("conflict");
    }
    let msg = json!({
        "need": nr.get("id").cloned().unwrap_or(Value::Null), "grant": nr.get("grant_id").cloned().unwrap_or(Value::Null),
        "rev": g.get("rev").cloned().unwrap_or(Value::Null), "approved": approved,
    });
    if !verify_body(
        NEED_APPROVE_DOMAIN,
        &msg,
        str_of(g, "principal").unwrap_or(""),
        sig.and_then(Value::as_str),
    ) {
        return fail_code("bad_signature");
    }
    let (approved, needs) = match (
        approved.as_array(),
        nr.get("needs").and_then(Value::as_array),
    ) {
        (Some(a), Some(n)) if a.len() == n.len() => (a, n),
        _ => return fail_code(LOWER_ONLY),
    };
    let mut delta = Authority::default();
    for (a, want) in approved.iter().zip(needs) {
        let (verb, resource) = match (
            a.get("verb").and_then(Value::as_str),
            a.get("resource").and_then(Value::as_str),
        ) {
            (Some(v), Some(r))
                if a.get("verb") == want.get("verb")
                    && a.get("resource") == want.get("resource") =>
            {
                (v, r)
            }
            _ => return fail_code(LOWER_ONLY),
        };
        if let Some(l) = a.get("limits") {
            let l = match l.as_object() {
                Some(l) => l,
                None => return fail_code(LOWER_ONLY),
            };
            for (k, v) in l {
                let (v, w) = match (
                    v.as_f64(),
                    want.get("limits")
                        .and_then(|wl| wl.get(k))
                        .and_then(Value::as_f64),
                ) {
                    (Some(v), Some(w)) if v <= w => (v, w),
                    _ => return fail_code(LOWER_ONLY),
                };
                if v < w && !truthy(want.get("adjustable")) {
                    return fail_code("need_not_adjustable");
                }
                // a limit the need names but the principal omitted is not granted at all (omission is the lowest amount)
                let e = delta.limits.entry(k.clone()).or_insert(0.0);
                *e = e.max(v);
            }
        }
        delta.verbs.push(verb.to_string());
        delta.resources.push(resource.to_string());
    }
    if !step_up_ok {
        return fail_code("step_up_required");
    }
    match g
        .get("authority")
        .and_then(Authority::from_json)
        .and_then(|cur| authority_digest(&merge_authority(&cur, &delta).to_json()))
    {
        Some(d) => json!({"ok": true, "authority_digest": d}),
        None => fail_code("bad_request"),
    }
}
