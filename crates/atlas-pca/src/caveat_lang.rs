//! Caveat language v2 (track K1): third-party discharges (`needs_discharge`), `sealed`, holder-signed `narrow` blocks,
//! `max_uses`, `derive` and `spiffe_bound`. A port of the TypeScript reference; behaviour AND reason text are normative.
//!
//! Every feature is a RESTRICTION: a caveat only ever removes authority, every one is conjunctive with the rest of the chain,
//! and a verifier that does not know a type refuses the chain (unknown types are unsatisfied). The verifier never contacts a
//! third party; a discharge travels with the action. Signatures use the same pinned-signer artifact rules as the escalation
//! answer (`atlas-pca/discharge/v1\0`, `atlas-pca/narrow/v1\0`; a post-quantum or hybrid suite verifies only under the PQ key
//! the pin carries; a suite this build lacks is `unsupported_suite`).
//!
//! Total: a malformed caveat, discharge, narrow block or context is a refusal, never a panic and never an allow.

use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Map, Value};

use super::intent_strict::{
    artifact_ref, artifact_suite_error, bstr, closed_members_error, is_path_segment, is_scalar, nonneg, resolve_param_path, s, same, sint,
    verify_artifact_sig,
};
use super::{b64_encode, decode_b64u_strict, decode_pca_header, strict_parse, evaluate_agent_caveats, hash_canonical_strict, holder_pq_commitment, policy_caveats, sha, StateStore};

pub const CAVEAT_NEEDS_DISCHARGE: &str = "needs_discharge";
pub const CAVEAT_SEALED: &str = "sealed";
pub const CAVEAT_MAX_USES: &str = "max_uses";
pub const CAVEAT_DERIVE: &str = "derive";
pub const CAVEAT_SPIFFE_BOUND: &str = "spiffe_bound";
/// Caveat types this module evaluates (the stock evaluators refuse them).
pub const K1_CAVEAT_TYPES: [&str; 5] = [CAVEAT_NEEDS_DISCHARGE, CAVEAT_SEALED, CAVEAT_MAX_USES, CAVEAT_DERIVE, CAVEAT_SPIFFE_BOUND];

pub const DISCHARGE_DOMAIN: &str = "atlas-pca/discharge/v1\0";
pub const DISCHARGE_REF_DOMAIN: &str = "atlas-pca/discharge-ref/v1";
pub const DISCHARGE_ACTION_DOMAIN: &str = "atlas-pca/discharge-action/v1";
pub const NARROW_DOMAIN: &str = "atlas-pca/narrow/v1\0";
pub const MAX_USES_DOMAIN: &str = "atlas-pca/max-uses/v1\0";
/// A discharge or narrow block lives at most 24 hours.
pub const K1_MAX_LIFETIME_MS: i64 = 86_400_000;
pub const MAX_USES_LIMIT: i64 = 256;
pub const NARROW_MAX_CAVEATS: usize = 16;
pub const DERIVE_MAX_DEFS: usize = 8;
pub const DERIVE_MAX_NODES: usize = 32;
pub const DERIVE_MAX_DEPTH: usize = 4;
pub const DERIVE_MAX_WINDOW_MS: i64 = 30 * 86_400_000;
pub const DERIVE_MAX_HISTORY: usize = 10_000;
pub const SPIFFE_MAX_ID_BYTES: usize = 2048;

const MAX_SAFE_K1: u64 = 9_007_199_254_740_991;
const ISSUER_CLASSES: [&str; 5] = ["human", "org", "workload", "model", "artifact"];

/// A safe-integer clock (anything else fails closed).
fn clock_ok(now: i64) -> bool {
    now.unsigned_abs() <= MAX_SAFE_K1
}

const CLOCK_REASON: &str = "the verifier clock is not a safe integer (fail closed)";

fn is_str256(v: Option<&Value>) -> bool {
    bstr(v, 256)
}

/// A wire scalar usable as a claim: a boolean, a safe integer or a non-empty string of at most 256 UTF-8 bytes.
fn scalar_claim(v: Option<&Value>) -> bool {
    is_scalar(v) && (!matches!(v, Some(Value::String(_))) || is_str256(v))
}

fn name_ok(x: &str) -> bool {
    let b = x.as_bytes();
    !b.is_empty() && b.len() <= 64 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn is_name(v: Option<&Value>) -> bool {
    s(v).is_some_and(name_ok)
}

/// `^[a-z0-9][a-z0-9_.-]{0,63}$`, anchored at both ends (a trailing newline is not tolerated).
fn is_id(v: Option<&Value>) -> bool {
    match s(v) {
        Some(x) => {
            let b = x.as_bytes();
            !b.is_empty()
                && b.len() <= 64
                && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
                && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(*c, b'_' | b'.' | b'-'))
        }
        None => false,
    }
}

fn is_digest(v: Option<&Value>) -> bool {
    s(v).and_then(|x| decode_b64u_strict(x, Some(32))).is_some()
}

/// `^[A-Za-z0-9._-]+$`
fn seg_ok(x: &str) -> bool {
    !x.is_empty() && x.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

// ======================================================================================
// SPIFFE ID syntax
// ======================================================================================

fn spiffe_str_error(x: &str) -> Option<String> {
    if x.len() > SPIFFE_MAX_ID_BYTES {
        return Some("SPIFFE ID is too long".into());
    }
    let rest = match x.strip_prefix("spiffe://") {
        Some(r) => r,
        None => return Some("SPIFFE ID must begin with spiffe://".into()),
    };
    let (td, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if td.is_empty() || td.len() > 255 || !td.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')) {
        return Some("invalid trust domain".into());
    }
    if path.is_empty() {
        return None;
    }
    if path.ends_with('/') {
        return Some("path must not end with a slash".into());
    }
    for seg in path.split('/').skip(1) {
        if seg == "." || seg == ".." || !seg_ok(seg) {
            return Some("invalid path segment".into());
        }
    }
    None
}

/// `None` when `v` is a valid SPIFFE ID: `spiffe://` + a trust domain of lowercase letters, digits, `.`, `-`, `_` + an optional
/// path of non-empty segments over `[A-Za-z0-9._-]` that are not `.` or `..`, no trailing slash, at most 2048 bytes, no query
/// or fragment.
pub fn spiffe_id_error(v: &Value) -> Option<String> {
    match v.as_str() {
        Some(x) if !x.is_empty() => spiffe_str_error(x),
        _ => Some("SPIFFE ID must be a non-empty string".into()),
    }
}

// ======================================================================================
// Hop analysis: which hop introduced a caveat
// ======================================================================================

/// A caveat of the leaf hop with the hop that introduced it.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundCaveat {
    pub caveat: Value,
    /// Index of the hop that introduced the caveat (0 = the root grant).
    pub hop: usize,
    /// The capability content hash of that hop.
    pub cap_hash: String,
}

/// The hops the policy layer sees: the chain (root first), else the grant alone.
fn hops_of<'a>(grant: &'a Value, chain: &'a Value) -> Vec<&'a Value> {
    match chain.as_array() {
        Some(a) if !a.is_empty() => a.iter().collect(),
        _ => vec![grant],
    }
}

/// Every caveat of the leaf hop with the hop that introduced it. Caveat lists are cumulative and append-only, so the caveat at
/// position `p` was introduced by the first hop whose list is longer than `p`. `None` for a malformed chain. The hop hash is the
/// STRICT canonical capability hash (a hop outside the strict profile is a malformed chain, as in the reference).
pub fn bound_caveats(grant: &Value, chain: &Value) -> Option<Vec<BoundCaveat>> {
    let hops = hops_of(grant, chain);
    let leaf = *hops.last()?;
    let list = leaf.get("caveats")?.as_array()?;
    let mut hashes: HashMap<usize, String> = HashMap::new();
    let mut out = Vec::with_capacity(list.len());
    for (p, caveat) in list.iter().enumerate() {
        let h = hops
            .iter()
            .position(|x| x.get("caveats").and_then(Value::as_array).is_some_and(|a| a.len() > p))
            .unwrap_or(hops.len() - 1);
        if !hashes.contains_key(&h) {
            hashes.insert(h, hash_canonical_strict(hops[h])?);
        }
        out.push(BoundCaveat { caveat: caveat.clone(), hop: h, cap_hash: hashes[&h].clone() });
    }
    Some(out)
}

/// A K1-type caveat: an object whose string `type` is one of [`K1_CAVEAT_TYPES`].
pub fn is_k1_caveat(c: &Value) -> bool {
    c.get("type").and_then(Value::as_str).is_some_and(|t| K1_CAVEAT_TYPES.contains(&t))
}

fn type_of(c: &Value) -> String {
    c.get("type").and_then(Value::as_str).unwrap_or("<malformed>").to_string()
}

// ======================================================================================
// needs_discharge: the third-party caveat and its discharge
// ======================================================================================

fn require_error(r: &Value) -> Option<String> {
    let m = match r.as_object() {
        Some(m) => m,
        None => return Some("requirement must be an object".into()),
    };
    if let Some(e) = closed_members_error(m, &["claim", "op", "value"], &[], "require") {
        return Some(e);
    }
    if !is_name(m.get("claim")) {
        return Some("claim name is malformed".into());
    }
    let op = s(m.get("op"));
    if !matches!(op, Some("eq" | "neq" | "gte" | "lte" | "in")) {
        return Some("op must be eq, neq, gte, lte or in".into());
    }
    if op == Some("in") {
        let ok = match m.get("value").and_then(Value::as_array) {
            Some(a) => !a.is_empty() && a.len() <= 16 && a.iter().all(|x| scalar_claim(Some(x))),
            None => false,
        };
        if !ok {
            return Some("'in' needs 1..16 scalar values".into());
        }
    } else if op == Some("gte") || op == Some("lte") {
        if sint(m.get("value")).is_none() {
            return Some(format!("'{}' needs a safe integer", op.unwrap_or_default()));
        }
    } else if !scalar_claim(m.get("value")) {
        return Some("value must be a scalar".into());
    }
    None
}

/// `None` when the caveat is well-formed: closed members, canonical names, bounded sizes.
pub fn needs_discharge_error(c: &Value) -> Option<String> {
    let m = match c.as_object() {
        Some(m) => m,
        None => return Some("caveat must be an object".into()),
    };
    if let Some(e) = closed_members_error(m, &["type", "id", "issuer", "issuer_class", "bind", "ttl_ms", "require"], &["issuer_spiffe"], "needs_discharge") {
        return Some(e);
    }
    if s(m.get("type")) != Some(CAVEAT_NEEDS_DISCHARGE) {
        return Some("not a needs_discharge caveat".into());
    }
    if !is_id(m.get("id")) {
        return Some("id is malformed".into());
    }
    if !is_id(m.get("issuer")) {
        return Some("issuer label is malformed".into());
    }
    if !s(m.get("issuer_class")).is_some_and(|k| ISSUER_CLASSES.contains(&k)) {
        return Some("issuer_class must be human, org, workload, model or artifact".into());
    }
    if !matches!(s(m.get("bind")), Some("chain_hop" | "action")) {
        return Some("bind must be 'chain_hop' or 'action'".into());
    }
    if !sint(m.get("ttl_ms")).is_some_and(|t| (1..=K1_MAX_LIFETIME_MS).contains(&t)) {
        return Some("ttl_ms must be 1..86400000".into());
    }
    match m.get("require").and_then(Value::as_array) {
        Some(reqs) if reqs.len() <= 16 => {
            for r in reqs {
                if let Some(e) = require_error(r) {
                    return Some(e);
                }
            }
        }
        _ => return Some("require must be an array of at most 16 requirements".into()),
    }
    if let Some(sp) = m.get("issuer_spiffe") {
        if let Some(e) = spiffe_id_error(sp) {
            return Some(format!("issuer_spiffe: {e}"));
        }
    }
    None
}

/// A verifier-side pin for a discharge issuer. `label` is what caveats name; the keys never appear in a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DischargePin {
    pub label: String,
    /// `human`, `org`, `workload` or `model`.
    pub class: String,
    /// The issuer's Ed25519 key (b64u).
    pub pk: String,
    /// The PQ key (b64u) a post-quantum or hybrid discharge must carry.
    pub pq_pk: Option<String>,
    pub spiffe_id: Option<String>,
}

impl DischargePin {
    /// A pin from its JSON form `{label, class, pk, pq_pk?, spiffe_id?}`; `None` when `label`, `class` or `pk` is not a string.
    pub fn from_json(v: &Value) -> Option<DischargePin> {
        let m = v.as_object()?;
        let get = |k: &str| m.get(k).and_then(Value::as_str).map(String::from);
        Some(DischargePin { label: get("label")?, class: get("class")?, pk: get("pk")?, pq_pk: get("pq_pk"), spiffe_id: get("spiffe_id") })
    }
}

/// The digest of the exact PCActn (counter and signature included): a bind-`action` discharge authorises that one action.
pub fn discharge_action_digest(pcactn: &Value) -> Option<String> {
    artifact_ref(DISCHARGE_ACTION_DOMAIN, "pcactn", pcactn)
}

/// Content address of a discharge (signature included); what a revocation list names.
pub fn discharge_digest(d: &Value) -> Option<String> {
    artifact_ref(DISCHARGE_REF_DOMAIN, "discharge", d)
}

const D_REQUIRED: [&str; 11] = ["v", "kind", "caveat_id", "issuer", "cap_hash", "bind", "claims", "iat", "not_after", "nonce", "sig"];
const D_OPTIONAL: [&str; 4] = ["action_digest", "alg", "pq_pk", "pq_sig"];

fn nonce_ok(v: Option<&Value>) -> bool {
    s(v).and_then(|x| decode_b64u_strict(x, None)).is_some_and(|b| b.len() >= 16)
}

/// `None` = well-formed.
pub fn discharge_shape_error(a: &Value) -> Option<String> {
    let m = match a.as_object() {
        Some(m) => m,
        None => return Some("not an object".into()),
    };
    if let Some(e) = closed_members_error(m, &D_REQUIRED, &D_OPTIONAL, "discharge") {
        return Some(e);
    }
    if sint(m.get("v")) != Some(1) || s(m.get("kind")) != Some("pca-discharge") {
        return Some("not a pca-discharge v1".into());
    }
    if !is_id(m.get("caveat_id")) {
        return Some("caveat_id is malformed".into());
    }
    if !is_id(m.get("issuer")) {
        return Some("issuer label is malformed".into());
    }
    if !is_digest(m.get("cap_hash")) {
        return Some("cap_hash must be canonical base64url (32 bytes)".into());
    }
    let bind = s(m.get("bind"));
    if !matches!(bind, Some("chain_hop" | "action")) {
        return Some("bind must be 'chain_hop' or 'action'".into());
    }
    let ad_bad = if bind == Some("action") { !is_digest(m.get("action_digest")) } else { m.get("action_digest").is_some() };
    if ad_bad {
        return Some("action_digest is required for bind action and forbidden for chain_hop".into());
    }
    let claims = match m.get("claims").and_then(Value::as_object) {
        Some(c) if c.len() <= 16 => c,
        _ => return Some("claims must be an object of at most 16 members".into()),
    };
    for (k, v) in claims {
        if !name_ok(k) || !scalar_claim(Some(v)) {
            return Some(format!("claim '{k}' is malformed"));
        }
    }
    let (iat, na) = match (nonneg(m.get("iat")), nonneg(m.get("not_after"))) {
        (Some(i), Some(n)) => (i, n),
        _ => return Some("iat and not_after must be non-negative safe integers".into()),
    };
    if na <= iat {
        return Some("not_after must be greater than iat".into());
    }
    if na - iat > K1_MAX_LIFETIME_MS {
        return Some(format!("a discharge lives at most {K1_MAX_LIFETIME_MS} ms"));
    }
    if !nonce_ok(m.get("nonce")) {
        return Some("nonce must be canonical base64url of at least 16 bytes".into());
    }
    if !m.get("sig").is_some_and(Value::is_string) {
        return Some("sig must be a string".into());
    }
    artifact_suite_error(m)
}

fn claim_holds(r: &Value, claims: &Map<String, Value>) -> bool {
    let v = match r.get("claim").and_then(Value::as_str).and_then(|k| claims.get(k)) {
        Some(v) => v,
        None => return false,
    };
    let want = r.get("value");
    match s(r.get("op")) {
        Some("eq") => same(Some(v), want),
        Some("neq") => !same(Some(v), want),
        Some("gte") => matches!((sint(Some(v)), sint(want)), (Some(a), Some(b)) if a >= b),
        Some("lte") => matches!((sint(Some(v)), sint(want)), (Some(a), Some(b)) if a <= b),
        Some("in") => want.and_then(Value::as_array).is_some_and(|xs| xs.iter().any(|x| same(Some(v), Some(x)))),
        _ => false,
    }
}

/// What a discharge must be bound to.
#[derive(Debug, Clone)]
pub struct DischargeBinding<'a> {
    /// The capability hash of the hop that carries the caveat.
    pub cap_hash: &'a str,
    /// [`discharge_action_digest`] of the PCActn being decided (needed for bind `action`).
    pub action_digest: Option<&'a str>,
    pub pins: &'a [DischargePin],
    pub now: i64,
    /// [`discharge_digest`] values the verifier has revoked.
    pub revoked: Option<&'a [String]>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DischargeVerdict {
    Ok { digest: String, claims: Map<String, Value> },
    Fail { reason: String },
}

fn dfail(reason: impl Into<String>) -> DischargeVerdict {
    DischargeVerdict::Fail { reason: reason.into() }
}

/// Verify one discharge against one caveat. The verifier's own pins decide the key; the discharge is bound to the hop carrying
/// the caveat (and for `action` to the PCActn); it must be inside its window and within the caveat's `ttl_ms`; and its claims must
/// satisfy every requirement. Total.
pub fn verify_discharge(discharge: &Value, caveat: &Value, bind: &DischargeBinding<'_>) -> DischargeVerdict {
    catch_unwind(AssertUnwindSafe(|| verify_discharge_inner(discharge, caveat, bind)))
        .unwrap_or_else(|_| dfail("discharge error (fail closed): unknown"))
}

fn verify_discharge_inner(discharge: &Value, caveat: &Value, bind: &DischargeBinding<'_>) -> DischargeVerdict {
    if !clock_ok(bind.now) {
        return dfail(CLOCK_REASON);
    }
    if let Some(ce) = needs_discharge_error(caveat) {
        return dfail(format!("malformed needs_discharge caveat: {ce}"));
    }
    if let Some(de) = discharge_shape_error(discharge) {
        return dfail(format!("malformed discharge: {de}"));
    }
    let (c, d) = match (caveat.as_object(), discharge.as_object()) {
        (Some(c), Some(d)) => (c, d),
        _ => return dfail("malformed discharge: not an object"),
    };
    let cs = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default();
    let ds = |k: &str| d.get(k).and_then(Value::as_str).unwrap_or_default();
    if ds("caveat_id") != cs("id") {
        return dfail("the discharge is for another caveat");
    }
    if ds("issuer") != cs("issuer") {
        return dfail("the discharge names another issuer");
    }
    let pins: Vec<&DischargePin> = bind.pins.iter().filter(|p| p.label == cs("issuer")).collect();
    if pins.is_empty() {
        return dfail("the issuer is not pinned by this verifier");
    }
    if pins.len() > 1 {
        return dfail("the issuer label is pinned more than once (ambiguous)");
    }
    let pin = pins[0];
    if pin.class != cs("issuer_class") {
        return dfail("the pinned issuer is not of the class the caveat requires");
    }
    if let Some(want) = c.get("issuer_spiffe").and_then(Value::as_str) {
        if pin.spiffe_id.as_deref() != Some(want) {
            return dfail("the pinned issuer does not carry the SPIFFE ID the caveat requires");
        }
    }
    let pq = pin.pq_pk.clone().map(Value::String);
    if !verify_artifact_sig(DISCHARGE_DOMAIN, d, &pin.pk, pq.as_ref()) {
        return dfail("discharge signature invalid");
    }
    if ds("bind") != cs("bind") {
        return dfail("the discharge binds differently than the caveat requires");
    }
    if ds("cap_hash") != bind.cap_hash {
        return dfail("the discharge is bound to another hop");
    }
    if cs("bind") == "action" && d.get("action_digest").and_then(Value::as_str) != bind.action_digest {
        return dfail("the discharge is bound to another action");
    }
    let (iat, not_after) = (sint(d.get("iat")).unwrap_or(0), sint(d.get("not_after")).unwrap_or(0));
    if bind.now < iat {
        return dfail("the discharge is from the future");
    }
    if bind.now > not_after {
        return dfail("the discharge has expired");
    }
    if not_after - iat > sint(c.get("ttl_ms")).unwrap_or(0) {
        return dfail("the discharge lives longer than the caveat allows");
    }
    let digest = match discharge_digest(discharge) {
        Some(x) => x,
        None => return dfail("discharge error (fail closed): the discharge cannot be hashed"),
    };
    if bind.revoked.is_some_and(|r| r.iter().any(|x| *x == digest)) {
        return dfail("the discharge is revoked");
    }
    let empty = Map::new();
    let claims = d.get("claims").and_then(Value::as_object).unwrap_or(&empty);
    for r in c.get("require").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        if !claim_holds(r, claims) {
            let name = r.get("claim").and_then(Value::as_str).unwrap_or_default();
            return dfail(format!("claim '{name}' does not satisfy the caveat"));
        }
    }
    DischargeVerdict::Ok { digest, claims: claims.clone() }
}

// ======================================================================================
// narrow: holder-signed per-action self-attenuation (no new hop)
// ======================================================================================

/// Types a narrow block must not carry: structure that only a real hop can introduce, and nested narrowing.
const NARROW_FORBIDDEN: [&str; 4] = ["envelope", CAVEAT_SEALED, "budget_alloc", "intent_session"];
const N_REQUIRED: [&str; 9] = ["v", "kind", "cap_hash", "holder", "caveats", "iat", "not_after", "nonce", "sig"];
const N_OPTIONAL: [&str; 4] = ["action_digest", "alg", "pq_pk", "pq_sig"];

/// `None` = well-formed.
pub fn narrow_shape_error(a: &Value) -> Option<String> {
    let m = match a.as_object() {
        Some(m) => m,
        None => return Some("not an object".into()),
    };
    if let Some(e) = closed_members_error(m, &N_REQUIRED, &N_OPTIONAL, "narrow") {
        return Some(e);
    }
    if sint(m.get("v")) != Some(1) || s(m.get("kind")) != Some("pca-narrow") {
        return Some("not a pca-narrow v1".into());
    }
    if !is_digest(m.get("cap_hash")) {
        return Some("cap_hash must be canonical base64url (32 bytes)".into());
    }
    if !bstr(m.get("holder"), 64) || !is_digest(m.get("holder")) {
        return Some("holder must be canonical base64url (32 bytes)".into());
    }
    match m.get("caveats").and_then(Value::as_array) {
        Some(cs) if !cs.is_empty() && cs.len() <= NARROW_MAX_CAVEATS => {
            for c in cs {
                let ty = match c.get("type").and_then(Value::as_str) {
                    Some(t) if c.is_object() => t,
                    _ => return Some("every caveat must be an object with a string type".into()),
                };
                if NARROW_FORBIDDEN.contains(&ty) {
                    return Some(format!("a narrow block cannot carry a '{ty}' caveat"));
                }
            }
        }
        _ => return Some(format!("caveats must be 1..{NARROW_MAX_CAVEATS} caveats")),
    }
    if m.get("action_digest").is_some() && !is_digest(m.get("action_digest")) {
        return Some("action_digest must be canonical base64url (32 bytes)".into());
    }
    let (iat, na) = match (nonneg(m.get("iat")), nonneg(m.get("not_after"))) {
        (Some(i), Some(n)) => (i, n),
        _ => return Some("iat and not_after must be non-negative safe integers".into()),
    };
    if na <= iat {
        return Some("not_after must be greater than iat".into());
    }
    if na - iat > K1_MAX_LIFETIME_MS {
        return Some(format!("a narrow block lives at most {K1_MAX_LIFETIME_MS} ms"));
    }
    if !nonce_ok(m.get("nonce")) {
        return Some("nonce must be canonical base64url of at least 16 bytes".into());
    }
    if !m.get("sig").is_some_and(Value::is_string) {
        return Some("sig must be a string".into());
    }
    artifact_suite_error(m)
}

#[derive(Debug, Clone, PartialEq)]
pub enum NarrowVerdict {
    Ok { caveats: Vec<Value> },
    Fail { reason: String },
}

fn nfail(reason: impl Into<String>) -> NarrowVerdict {
    NarrowVerdict::Fail { reason: reason.into() }
}

/// What a narrow block must be bound to.
#[derive(Debug, Clone, Default)]
pub struct NarrowBinding<'a> {
    pub now: i64,
    /// [`discharge_action_digest`] of the PCActn being decided.
    pub action_digest: Option<&'a str>,
}

/// Verify a narrow block against the chain's leaf: signed by the leaf holder (a non-Ed25519 suite only under the PQ key the
/// leaf's `holder_pq` commits to), bound to the leaf hop and, when it names one, to this PCActn, inside its window. The caveats
/// it carries then join the chain's. A narrow block can only ADD restrictions. Total.
pub fn verify_narrow(narrow: &Value, grant: &Value, chain: &Value, bind: &NarrowBinding<'_>) -> NarrowVerdict {
    catch_unwind(AssertUnwindSafe(|| verify_narrow_inner(narrow, grant, chain, bind)))
        .unwrap_or_else(|_| nfail("narrow error (fail closed): unknown"))
}

fn verify_narrow_inner(narrow: &Value, grant: &Value, chain: &Value, bind: &NarrowBinding<'_>) -> NarrowVerdict {
    if !clock_ok(bind.now) {
        return nfail(CLOCK_REASON);
    }
    if let Some(e) = narrow_shape_error(narrow) {
        return nfail(format!("malformed narrow block: {e}"));
    }
    let n = match narrow.as_object() {
        Some(n) => n,
        None => return nfail("malformed narrow block: not an object"),
    };
    let hops = hops_of(grant, chain);
    let leaf = match hops.last() {
        Some(l) => *l,
        None => return nfail("narrow error (fail closed): no leaf hop"),
    };
    let holder = n.get("holder").and_then(Value::as_str).unwrap_or_default();
    if leaf.get("holder").and_then(Value::as_str) != Some(holder) {
        return nfail("the narrow block is not signed by the leaf holder");
    }
    let leaf_hash = match hash_canonical_strict(leaf) {
        Some(h) => h,
        None => return nfail("narrow error (fail closed): the leaf hop cannot be hashed"),
    };
    if n.get("cap_hash").and_then(Value::as_str) != Some(leaf_hash.as_str()) {
        return nfail("the narrow block is bound to another hop");
    }
    let pq: Option<Value> = match (n.get("pq_pk").and_then(Value::as_str), leaf.get("holder_pq").and_then(Value::as_str)) {
        (Some(p), Some(h)) if holder_pq_commitment(p) == h => Some(Value::String(p.to_string())),
        _ => None,
    };
    if !verify_artifact_sig(NARROW_DOMAIN, n, holder, pq.as_ref()) {
        return nfail("narrow signature invalid");
    }
    if let Some(ad) = n.get("action_digest").and_then(Value::as_str) {
        if bind.action_digest != Some(ad) {
            return nfail("the narrow block is bound to another action");
        }
    }
    let (iat, not_after) = (sint(n.get("iat")).unwrap_or(0), sint(n.get("not_after")).unwrap_or(0));
    if bind.now < iat {
        return nfail("the narrow block is from the future");
    }
    if bind.now > not_after {
        return nfail("the narrow block has expired");
    }
    NarrowVerdict::Ok { caveats: n.get("caveats").and_then(Value::as_array).cloned().unwrap_or_default() }
}

// ======================================================================================
// max_uses: n atomic first-use slots in the verifier's replay store
// ======================================================================================

/// `None` when the caveat is well-formed.
pub fn max_uses_error(c: &Value) -> Option<String> {
    let m = match c.as_object() {
        Some(m) => m,
        None => return Some("caveat must be an object".into()),
    };
    if let Some(e) = closed_members_error(m, &["type", "id", "n", "until"], &[], "max_uses") {
        return Some(e);
    }
    if s(m.get("type")) != Some(CAVEAT_MAX_USES) {
        return Some("not a max_uses caveat".into());
    }
    if !is_id(m.get("id")) {
        return Some("id is malformed".into());
    }
    if !sint(m.get("n")).is_some_and(|n| (1..=MAX_USES_LIMIT).contains(&n)) {
        return Some(format!("n must be 1..{MAX_USES_LIMIT}"));
    }
    if nonneg(m.get("until")).is_none() {
        return Some("until must be a non-negative safe integer".into());
    }
    None
}

/// The store key of use slot `i` of caveat `id` carried by the hop whose capability hash is `cap_hash`:
/// b64u(sha256(domain NUL cap NUL id NUL i)).
pub fn max_uses_slot_key(cap_hash: &str, id: &str, i: u64) -> String {
    b64_encode(&sha(format!("{MAX_USES_DOMAIN}{cap_hash}\0{id}\0{i}").as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsesVerdict {
    Ok { spent: usize },
    Fail { reason: String },
}

fn ufail(reason: impl Into<String>) -> UsesVerdict {
    UsesVerdict::Fail { reason: reason.into() }
}

/// Spend one use of every `max_uses` caveat in `bound`, in order, after the rest of the decision allows. Each caveat takes the
/// first free slot of its `n` (an atomic TTL'd [`StateStore::consume_once`] of the slot key, remembered until `until`, so concurrent actions never share a slot, across
/// processes when the store is durable and shared). The first exhausted, expired or malformed caveat refuses; slots already
/// taken stay spent (a use is spent when the action is admitted, and a refusal after that cannot give it back: fail closed).
pub fn reserve_max_uses(store: &dyn StateStore, bound: &[BoundCaveat], now: i64) -> UsesVerdict {
    catch_unwind(AssertUnwindSafe(|| reserve_inner(store, bound, now))).unwrap_or_else(|_| ufail("max_uses error (fail closed): unknown"))
}

fn reserve_inner(store: &dyn StateStore, bound: &[BoundCaveat], now: i64) -> UsesVerdict {
    if !clock_ok(now) {
        return ufail(CLOCK_REASON);
    }
    let mut spent = 0usize;
    let mut ids: HashSet<String> = HashSet::new();
    for b in bound {
        if b.caveat.get("type").and_then(Value::as_str) != Some(CAVEAT_MAX_USES) {
            continue;
        }
        if let Some(err) = max_uses_error(&b.caveat) {
            return ufail(format!("malformed max_uses caveat: {err}"));
        }
        let id = b.caveat.get("id").and_then(Value::as_str).unwrap_or_default();
        let n = sint(b.caveat.get("n")).unwrap_or(0);
        let until = sint(b.caveat.get("until")).unwrap_or(0);
        if !ids.insert(format!("{}\0{}", b.cap_hash, id)) {
            return ufail(format!("duplicate max_uses id '{id}'"));
        }
        if now >= until {
            return ufail(format!("max_uses '{id}' has expired"));
        }
        let mut took = false;
        let mut i = 0u64;
        while (i as i64) < n && !took {
            match store.consume_once(&max_uses_slot_key(&b.cap_hash, id, i), until, now) {
                Ok(r) => took = r,
                Err(e) => return ufail(format!("max_uses error (fail closed): {e}")),
            }
            i += 1;
        }
        if !took {
            return ufail(format!("max_uses '{id}' is exhausted"));
        }
        spent += 1;
    }
    UsesVerdict::Ok { spent }
}

// ======================================================================================
// derive: bounded derived facts in Kleene three-valued logic
// ======================================================================================

fn expr_error(x: &Value, names: &HashSet<String>, depth: usize, count: &mut usize) -> Option<String> {
    if depth > DERIVE_MAX_DEPTH {
        return Some(format!("expression nests deeper than {DERIVE_MAX_DEPTH}"));
    }
    *count += 1;
    if *count > DERIVE_MAX_NODES {
        return Some(format!("more than {DERIVE_MAX_NODES} expression nodes"));
    }
    let m = match x.as_object() {
        Some(m) => m,
        None => return Some("expression must be an object".into()),
    };
    if m.contains_key("ref") {
        if let Some(e) = closed_members_error(m, &["ref"], &[], "ref") {
            return Some(e);
        }
        return if s(m.get("ref")).is_some_and(|r| names.contains(r)) { None } else { Some("ref names no earlier def".into()) };
    }
    if m.contains_key("const") {
        if let Some(e) = closed_members_error(m, &["const"], &[], "const") {
            return Some(e);
        }
        return if scalar_claim(m.get("const")) { None } else { Some("const must be a scalar".into()) };
    }
    let null = Value::Null;
    match s(m.get("op")) {
        Some(op @ ("and" | "or")) => {
            if let Some(e) = closed_members_error(m, &["op", "args"], &[], op) {
                return Some(e);
            }
            let args = match m.get("args").and_then(Value::as_array) {
                Some(a) if !a.is_empty() && a.len() <= 8 => a,
                _ => return Some(format!("{op} needs 1..8 arguments")),
            };
            for a in args {
                if let Some(r) = expr_error(a, names, depth + 1, count) {
                    return Some(r);
                }
            }
            None
        }
        Some("not") => {
            if let Some(e) = closed_members_error(m, &["op", "arg"], &[], "not") {
                return Some(e);
            }
            expr_error(m.get("arg").unwrap_or(&null), names, depth + 1, count)
        }
        Some(op @ ("eq" | "neq" | "lt" | "lte" | "gt" | "gte")) => {
            if let Some(e) = closed_members_error(m, &["op", "a", "b"], &[], op) {
                return Some(e);
            }
            if let Some(r) = expr_error(m.get("a").unwrap_or(&null), names, depth + 1, count) {
                return Some(r);
            }
            expr_error(m.get("b").unwrap_or(&null), names, depth + 1, count)
        }
        _ => Some("unknown expression".into()),
    }
}

fn def_kind_error(dm: &Map<String, Value>, kind: Option<&str>, names: &HashSet<String>, count: &mut usize) -> Option<String> {
    match kind {
        Some("count") => {
            let mut de = closed_members_error(dm, &["name", "kind", "window_ms"], &["verb", "resource_prefix"], "count");
            if de.is_none() && !sint(dm.get("window_ms")).is_some_and(|w| (1..=DERIVE_MAX_WINDOW_MS).contains(&w)) {
                de = Some("window_ms out of range".into());
            }
            if de.is_none() && dm.get("verb").is_some() && !is_str256(dm.get("verb")) {
                de = Some("verb must be a non-empty string".into());
            }
            if de.is_none() && dm.get("resource_prefix").is_some() && !is_str256(dm.get("resource_prefix")) {
                de = Some("resource_prefix must be a non-empty string".into());
            }
            de
        }
        Some("param") => {
            let mut de = closed_members_error(dm, &["name", "kind", "path"], &[], "param");
            let ok = s(dm.get("path")).is_some_and(|p| {
                let segs: Vec<&str> = p.split('.').collect();
                segs.len() <= 4 && segs.iter().all(|x| is_path_segment(x))
            });
            if de.is_none() && !ok {
                de = Some("param path is malformed".into());
            }
            de
        }
        Some("action") => {
            let mut de = closed_members_error(dm, &["name", "kind", "field"], &[], "action");
            if de.is_none() && !matches!(s(dm.get("field")), Some("verb" | "resource")) {
                de = Some("field must be 'verb' or 'resource'".into());
            }
            de
        }
        Some("claim") => {
            let mut de = closed_members_error(dm, &["name", "kind", "caveat_id", "claim"], &[], "claim");
            if de.is_none() && !(is_id(dm.get("caveat_id")) && is_name(dm.get("claim"))) {
                de = Some("claim reference is malformed".into());
            }
            de
        }
        Some("expr") => match closed_members_error(dm, &["name", "kind", "expr"], &[], "expr") {
            Some(e) => Some(e),
            None => expr_error(dm.get("expr").unwrap_or(&Value::Null), names, 1, count),
        },
        _ => Some("unknown def kind".into()),
    }
}

/// `None` when the caveat is well-formed: bounded, closed, and non-recursive (a def refers only to defs before it).
pub fn derive_error(c: &Value) -> Option<String> {
    let m = match c.as_object() {
        Some(m) => m,
        None => return Some("caveat must be an object".into()),
    };
    if let Some(e) = closed_members_error(m, &["type", "id", "defs", "check"], &[], "derive") {
        return Some(e);
    }
    if s(m.get("type")) != Some(CAVEAT_DERIVE) {
        return Some("not a derive caveat".into());
    }
    if !is_id(m.get("id")) {
        return Some("id is malformed".into());
    }
    let defs = match m.get("defs").and_then(Value::as_array) {
        Some(d) if d.len() <= DERIVE_MAX_DEFS => d,
        _ => return Some(format!("defs must be an array of at most {DERIVE_MAX_DEFS}")),
    };
    let mut names: HashSet<String> = HashSet::new();
    let mut count = 0usize;
    for d in defs {
        let dm = match d.as_object() {
            Some(dm) if is_name(dm.get("name")) => dm,
            _ => return Some("def name is malformed".into()),
        };
        let name = s(dm.get("name")).unwrap_or_default().to_string();
        if names.contains(&name) {
            return Some(format!("def '{name}' is defined twice"));
        }
        if let Some(de) = def_kind_error(dm, s(dm.get("kind")), &names, &mut count) {
            return Some(format!("def '{name}': {de}"));
        }
        names.insert(name);
    }
    expr_error(m.get("check").unwrap_or(&Value::Null), &names, 1, &mut count)
}

type Env = HashMap<String, Option<Value>>;

/// An expression value: a scalar, or `None` for unknown (Kleene's third value).
fn eval_expr(x: &Value, env: &Env) -> Option<Value> {
    if let Some(r) = x.get("ref").and_then(Value::as_str) {
        return env.get(r).cloned().flatten();
    }
    if let Some(c) = x.get("const") {
        return Some(c.clone());
    }
    let op = s(x.get("op")).unwrap_or_default();
    if op == "not" {
        return match x.get("arg").and_then(|a| eval_expr(a, env)) {
            Some(Value::Bool(b)) => Some(Value::Bool(!b)),
            _ => None,
        };
    }
    if op == "and" || op == "or" {
        let stop = op == "or";
        let mut unknown = false;
        for a in x.get("args").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
            match eval_expr(a, env) {
                Some(Value::Bool(v)) => {
                    if v == stop {
                        return Some(Value::Bool(stop));
                    }
                }
                _ => unknown = true,
            }
        }
        return if unknown { None } else { Some(Value::Bool(!stop)) };
    }
    let a = x.get("a").and_then(|v| eval_expr(v, env))?;
    let b = x.get("b").and_then(|v| eval_expr(v, env))?;
    match op {
        "eq" => return Some(Value::Bool(same(Some(&a), Some(&b)))),
        "neq" => return Some(Value::Bool(!same(Some(&a), Some(&b)))),
        _ => {}
    }
    let (ai, bi) = (sint(Some(&a))?, sint(Some(&b))?);
    match op {
        "lt" => Some(Value::Bool(ai < bi)),
        "lte" => Some(Value::Bool(ai <= bi)),
        "gt" => Some(Value::Bool(ai > bi)),
        "gte" => Some(Value::Bool(ai >= bi)),
        _ => None,
    }
}

/// What a `derive` caveat may read.
#[derive(Debug, Clone)]
pub struct DeriveInput<'a> {
    pub now: i64,
    /// `{verb, resource, params}`.
    pub action: Option<&'a Value>,
    /// The verifier's own record of the holder's admitted actions: `{t, verb, resource}`.
    pub history: Option<&'a [Value]>,
    /// `caveat id -> claims object` of the discharges that VERIFIED in this evaluation: the only claim source a `derive` may read.
    pub claims: &'a Map<String, Value>,
}

/// Evaluate a well-formed derive caveat: `Some(true)` only when `check` is exactly true; `Some(false)` is false, `None` unknown.
pub fn evaluate_derive(c: &Value, inp: &DeriveInput<'_>) -> Option<bool> {
    let mut env: Env = HashMap::new();
    for d in c.get("defs").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default() {
        let mut v: Option<Value> = None;
        match s(d.get("kind")) {
            Some("count") => {
                if let Some(h) = inp.history.filter(|h| h.len() <= DERIVE_MAX_HISTORY) {
                    let window = sint(d.get("window_ms")).unwrap_or(0);
                    let verb = s(d.get("verb"));
                    let prefix = s(d.get("resource_prefix"));
                    let mut n: i64 = 0;
                    let mut bad = false;
                    for e in h {
                        let (t, ev, er) = match (sint(e.get("t")), s(e.get("verb")), s(e.get("resource"))) {
                            (Some(t), Some(ev), Some(er)) if e.is_object() => (t, ev, er),
                            _ => {
                                bad = true;
                                break;
                            }
                        };
                        if t > inp.now - window && t <= inp.now && verb.map_or(true, |x| x == ev) && prefix.map_or(true, |x| er.starts_with(x)) {
                            n += 1;
                        }
                    }
                    if !bad {
                        v = Some(Value::from(n));
                    }
                }
            }
            Some("param") => {
                let path = format!("action.params.{}", s(d.get("path")).unwrap_or_default());
                v = inp
                    .action
                    .and_then(|a| a.get("params"))
                    .and_then(|p| resolve_param_path(p, &path))
                    .filter(|x| scalar_claim(Some(*x)))
                    .cloned();
            }
            Some("action") => {
                v = inp.action.and_then(|a| a.get(s(d.get("field")).unwrap_or_default())).filter(|x| is_str256(Some(*x))).cloned();
            }
            Some("claim") => {
                let cl = s(d.get("caveat_id")).and_then(|id| inp.claims.get(id)).and_then(Value::as_object);
                v = cl.and_then(|cl| s(d.get("claim")).and_then(|k| cl.get(k))).cloned();
            }
            Some("expr") => {
                v = d.get("expr").and_then(|x| eval_expr(x, &env));
            }
            _ => {}
        }
        env.insert(s(d.get("name")).unwrap_or_default().to_string(), v);
    }
    match c.get("check").and_then(|x| eval_expr(x, &env)) {
        Some(Value::Bool(b)) => Some(b),
        _ => None,
    }
}

// ======================================================================================
// spiffe_bound
// ======================================================================================

/// `None` when the caveat is well-formed: exactly one of `spiffe_id` / `spiffe_prefix`, a valid SPIFFE ID.
pub fn spiffe_bound_error(c: &Value) -> Option<String> {
    let m = match c.as_object() {
        Some(m) => m,
        None => return Some("caveat must be an object".into()),
    };
    if let Some(e) = closed_members_error(m, &["type"], &["spiffe_id", "spiffe_prefix"], "spiffe_bound") {
        return Some(e);
    }
    if s(m.get("type")) != Some(CAVEAT_SPIFFE_BOUND) {
        return Some("not a spiffe_bound caveat".into());
    }
    if m.contains_key("spiffe_id") == m.contains_key("spiffe_prefix") {
        return Some("exactly one of spiffe_id and spiffe_prefix".into());
    }
    spiffe_id_error(m.get("spiffe_id").or_else(|| m.get("spiffe_prefix")).unwrap_or(&Value::Null))
}

/// `spiffe_id`: the peer must equal it. `spiffe_prefix`: the peer must equal it or lie below it (`prefix + "/"`).
fn spiffe_satisfied(c: &Value, peer: Option<&str>) -> bool {
    let p = match peer {
        Some(p) if !p.is_empty() && spiffe_str_error(p).is_none() => p,
        _ => return false,
    };
    if spiffe_bound_error(c).is_some() {
        return false;
    }
    if let Some(id) = c.get("spiffe_id").and_then(Value::as_str) {
        return p == id;
    }
    match c.get("spiffe_prefix").and_then(Value::as_str) {
        Some(pre) => p == pre || p.strip_prefix(pre).is_some_and(|rest| rest.starts_with('/')),
        None => false,
    }
}

// ======================================================================================
// The K1 evaluator
// ======================================================================================

/// What the verifier brings to the evaluation. Nothing here is taken from the request except `discharges` and `narrow`
/// (the artifacts themselves, verified against the pins).
#[derive(Debug, Clone, Default)]
pub struct K1Input {
    /// The verifier's pins for discharge issuers.
    pub pins: Vec<DischargePin>,
    /// Discharges presented with the action.
    pub discharges: Vec<Value>,
    /// A narrow block presented with the action (`Some(Value::Null)` is present and malformed).
    pub narrow: Option<Value>,
    /// [`discharge_action_digest`] of the PCActn being decided.
    pub action_digest: Option<String>,
    /// [`discharge_digest`] values the verifier has revoked.
    pub revoked_discharges: Option<Vec<String>>,
    /// The SPIFFE ID of the presenting workload, from an SVID the verifier verified.
    pub spiffe_id: Option<String>,
    /// The verifier's own record of this holder's admitted actions: `{t, verb, resource}`.
    pub history: Option<Vec<Value>>,
}

/// The evaluation context: the verifier clock and the action being decided (`{verb, resource, params}`).
#[derive(Debug, Clone, Copy)]
pub struct K1Ctx<'a> {
    pub now: i64,
    pub action: Option<&'a Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct K1Result {
    pub ok: bool,
    /// Types of the unsatisfied caveats, in order (`<malformed>` for one without a string type).
    pub failed: Vec<String>,
    /// One reason per failure (same order).
    pub reasons: Vec<String>,
    /// Verified narrow-block caveats that are NOT K1 types: the caller evaluates them with its stock evaluator.
    pub plain: Vec<Value>,
    /// The K1 caveats evaluated, with their hops: hand the `max_uses` ones to [`reserve_max_uses`] once everything allowed.
    pub bound: Vec<BoundCaveat>,
}

struct Fails {
    failed: Vec<String>,
    reasons: Vec<String>,
}

impl Fails {
    fn add(&mut self, ty: &str, why: impl Into<String>) {
        self.failed.push(ty.to_string());
        self.reasons.push(why.into());
    }

    fn done(self, plain: Vec<Value>, bound: Vec<BoundCaveat>) -> K1Result {
        K1Result { ok: self.failed.is_empty(), failed: self.failed, reasons: self.reasons, plain, bound }
    }
}

/// Evaluate the K1 caveat types of the leaf hop (and of a verified narrow block). Non-K1 caveats are left to the stock
/// evaluators. `needs_discharge`, `sealed`, `max_uses` and `derive` ids must be unique over the chain and narrow block: a
/// duplicate fails every caveat that shares it. `max_uses` is only checked for well-formedness and expiry here;
/// [`reserve_max_uses`] spends it. `k1 = None` (no K1 input configured) fails every K1-type caveat; `Some(&K1Input::default())`
/// is configured and empty. Total.
pub fn evaluate_k1(grant: &Value, chain: &Value, k1: Option<&K1Input>, ctx: &K1Ctx<'_>) -> K1Result {
    catch_unwind(AssertUnwindSafe(|| evaluate_k1_inner(grant, chain, k1, ctx))).unwrap_or_else(|_| {
        let mut f = Fails { failed: vec![], reasons: vec![] };
        f.add("<malformed>", "caveat language error (fail closed): unknown");
        f.done(vec![], vec![])
    })
}

const UNCONFIGURED: &str = "the caveat language is not configured (no k1 input)";

fn evaluate_k1_inner(grant: &Value, chain: &Value, k1: Option<&K1Input>, ctx: &K1Ctx<'_>) -> K1Result {
    let mut f = Fails { failed: vec![], reasons: vec![] };
    let base = match bound_caveats(grant, chain) {
        Some(b) => b,
        None => {
            f.add("<malformed>", "malformed capability chain");
            return f.done(vec![], vec![]);
        }
    };
    if !clock_ok(ctx.now) {
        f.add("<malformed>", CLOCK_REASON);
        return f.done(vec![], vec![]);
    }
    let k1 = match k1 {
        Some(k) => k,
        None => {
            // no K1 input: every K1-type caveat of every hop is refused, none is evaluated
            for b in base.iter().filter(|b| is_k1_caveat(&b.caveat)) {
                f.add(&type_of(&b.caveat), UNCONFIGURED);
            }
            let kept: Vec<BoundCaveat> = base.into_iter().filter(|b| is_k1_caveat(&b.caveat)).collect();
            return f.done(vec![], kept);
        }
    };
    let hops = hops_of(grant, chain);
    let leaf_index = hops.len() - 1;
    let mut bound = base;
    let mut plain: Vec<Value> = Vec::new();
    if let Some(nr) = &k1.narrow {
        let nb = NarrowBinding { now: ctx.now, action_digest: k1.action_digest.as_deref() };
        match verify_narrow(nr, grant, chain, &nb) {
            NarrowVerdict::Fail { reason } => {
                f.add("narrow", reason);
                let kept: Vec<BoundCaveat> = bound.into_iter().filter(|b| is_k1_caveat(&b.caveat)).collect();
                return f.done(vec![], kept);
            }
            NarrowVerdict::Ok { caveats } => {
                let leaf_hash = match hash_canonical_strict(hops[leaf_index]) {
                    Some(h) => h,
                    None => {
                        f.add("<malformed>", "caveat language error (fail closed): the leaf hop cannot be hashed");
                        return f.done(vec![], vec![]);
                    }
                };
                for c in caveats {
                    if !is_k1_caveat(&c) {
                        plain.push(c.clone());
                    }
                    bound.push(BoundCaveat { caveat: c, hop: leaf_index, cap_hash: leaf_hash.clone() });
                }
            }
        }
    }
    let k1_bound: Vec<BoundCaveat> = bound.into_iter().filter(|b| is_k1_caveat(&b.caveat)).collect();
    // ids are unique per type across the chain and narrow block
    let mut seen: HashMap<String, usize> = HashMap::new();
    for b in &k1_bound {
        if let Some(id) = b.caveat.get("id").and_then(Value::as_str) {
            *seen.entry(format!("{}\0{}", type_of(&b.caveat), id)).or_insert(0) += 1;
        }
    }
    let dup = |ty: &str, c: &Value| seen.get(&format!("{}\0{}", ty, c.get("id").and_then(Value::as_str).unwrap_or_default())).copied().unwrap_or(0) > 1;
    let now = ctx.now;
    let mut claims: Map<String, Value> = Map::new();
    // pass 1: discharges (derive reads their claims)
    for b in &k1_bound {
        let c = &b.caveat;
        if c.get("type").and_then(Value::as_str) != Some(CAVEAT_NEEDS_DISCHARGE) {
            continue;
        }
        if let Some(bad) = needs_discharge_error(c) {
            f.add(CAVEAT_NEEDS_DISCHARGE, bad);
            continue;
        }
        let id = c.get("id").and_then(Value::as_str).unwrap_or_default();
        if dup(CAVEAT_NEEDS_DISCHARGE, c) {
            f.add(CAVEAT_NEEDS_DISCHARGE, format!("duplicate needs_discharge id '{id}'"));
            continue;
        }
        let mut why = "no discharge presented".to_string();
        let mut okd: Option<Map<String, Value>> = None;
        for d in &k1.discharges {
            if !d.is_object() || d.get("caveat_id") != c.get("id") {
                continue;
            }
            let binding = DischargeBinding {
                cap_hash: &b.cap_hash,
                action_digest: k1.action_digest.as_deref(),
                pins: &k1.pins,
                now,
                revoked: k1.revoked_discharges.as_deref(),
            };
            match verify_discharge(d, c, &binding) {
                DischargeVerdict::Ok { claims: cl, .. } => {
                    okd = Some(cl);
                    break;
                }
                DischargeVerdict::Fail { reason } => why = reason,
            }
        }
        match okd {
            Some(cl) => {
                claims.insert(id.to_string(), Value::Object(cl));
            }
            None => f.add(CAVEAT_NEEDS_DISCHARGE, why),
        }
    }
    // pass 2: everything else, in order
    for b in &k1_bound {
        let c = &b.caveat;
        let ty = type_of(c);
        let id = c.get("id").and_then(Value::as_str).unwrap_or_default();
        match ty.as_str() {
            CAVEAT_SEALED => {
                if let Some(e) = c.as_object().and_then(|m| closed_members_error(m, &["type"], &[], "sealed")) {
                    f.add(&ty, e);
                } else if b.hop != leaf_index {
                    f.add(&ty, "a hop was appended below a sealed hop");
                }
            }
            CAVEAT_MAX_USES => {
                if let Some(e) = max_uses_error(c) {
                    f.add(&ty, e);
                } else if dup(CAVEAT_MAX_USES, c) {
                    f.add(&ty, format!("duplicate max_uses id '{id}'"));
                } else if now >= sint(c.get("until")).unwrap_or(0) {
                    f.add(&ty, format!("max_uses '{id}' has expired"));
                }
            }
            CAVEAT_DERIVE => {
                if let Some(e) = derive_error(c) {
                    f.add(&ty, e);
                } else if dup(CAVEAT_DERIVE, c) {
                    f.add(&ty, format!("duplicate derive id '{id}'"));
                } else {
                    let inp = DeriveInput { now, action: ctx.action, history: k1.history.as_deref(), claims: &claims };
                    match evaluate_derive(c, &inp) {
                        Some(true) => {}
                        None => f.add(&ty, "derive check is unknown (a fact is missing)"),
                        Some(false) => f.add(&ty, "derive check is false"),
                    }
                }
            }
            CAVEAT_SPIFFE_BOUND => {
                if !spiffe_satisfied(c, k1.spiffe_id.as_deref()) {
                    f.add(&ty, "the presenting workload does not carry the required SPIFFE ID");
                }
            }
            _ => {}
        }
    }
    f.done(plain, k1_bound)
}

/// Evaluate a whole caveat list the way a verifier does with the caveat language on: the K1 types by [`evaluate_k1`], every
/// other caveat of [`policy_caveats`] PLUS the verified narrow block's plain caveats by the agent-native caveat evaluator.
/// `context` is the stock context (`now`, `delegation_depth`, `action {verb, resource, params}`, ...). Returns `(allow,
/// failed)` where `failed` (the unsatisfied caveat types, stock and K1 together) is sorted.
pub fn evaluate_caveats_k1(grant: &Value, chain: &Value, k1: Option<&K1Input>, context: &Value) -> (bool, Vec<String>) {
    let now = sint(context.get("now")).unwrap_or(i64::MAX); // a missing or non-integer clock fails closed
    let action = context.get("action");
    let k = evaluate_k1(grant, chain, k1, &K1Ctx { now, action });
    let stock = match policy_caveats(grant, chain) {
        Value::Array(list) => {
            let mut keep: Vec<Value> = list.into_iter().filter(|c| !is_k1_caveat(c)).collect();
            keep.extend(k.plain.iter().cloned());
            Value::Array(keep)
        }
        other => other,
    };
    let action_ctx = json!({"action": action.cloned().unwrap_or(Value::Null)});
    let (_, mut failed) = evaluate_agent_caveats(&stock, context, Some(&action_ctx), None);
    failed.extend(k.failed.iter().cloned());
    failed.sort();
    (failed.is_empty(), failed)
}

// ======================================================================================
// Presented artifacts: the PCA-Discharges / PCA-Narrow request headers
// ======================================================================================

/// What a request presents: discharges (header `PCA-Discharges`) and a narrow block (header `PCA-Narrow`). Not verified here.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PresentedK1 {
    pub discharges: Option<Vec<Value>>,
    pub narrow: Option<Value>,
}

/// The one value of header `name` (names match case-insensitively). Several case-variants with DIFFERENT values are ambiguous
/// and read as absent; an empty value is absent.
fn header_value<'a>(headers: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    let mut found: Option<&'a str> = None;
    for (k, v) in headers {
        if !k.eq_ignore_ascii_case(name) {
            continue;
        }
        match found {
            Some(prev) if prev != *v => return None,
            _ => found = Some(*v),
        }
    }
    found.filter(|v| !v.is_empty())
}

/// Read `PCA-Discharges` (strict unpadded base64url of a JSON array) and `PCA-Narrow` (the same, any JSON value) from request
/// headers given as `(name, value)` pairs. A malformed value is an `Err`: the guard then presents nothing, so the K1 caveat
/// stays unsatisfied. Total.
pub fn presented_k1<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<PresentedK1, String> {
    let headers: Vec<(&str, &str)> = headers.into_iter().collect();
    let mut out = PresentedK1::default();
    if let Some(d) = header_value(&headers, "pca-discharges") {
        let text = decode_pca_header(d).map_err(|e| e.to_string())?;
        match strict_parse(&text)? {
            Value::Array(a) => out.discharges = Some(a),
            _ => return Err("PCA-Discharges must be a JSON array".to_string()),
        }
    }
    if let Some(n) = header_value(&headers, "pca-narrow") {
        let text = decode_pca_header(n).map_err(|e| e.to_string())?;
        out.narrow = Some(strict_parse(&text)?);
    }
    Ok(out)
}

impl PresentedK1 {
    /// Fill a configured `own` input with what was presented, own winning where it sets a value (`{...presented, ...own}`).
    pub fn merged_into(&self, own: &K1Input) -> K1Input {
        let mut k = own.clone();
        if k.discharges.is_empty() {
            if let Some(d) = &self.discharges {
                k.discharges = d.clone();
            }
        }
        if k.narrow.is_none() {
            k.narrow = self.narrow.clone();
        }
        k
    }
}
