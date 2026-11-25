//! The producing side of the operational plane (port of @atlasauth/pca-grants): domain-separated Ed25519 signing, the signers for
//! leases, revocations, blueprints and break-glass records, policy bundle signing and assembly, the decision log (hash chain, Merkle
//! commitment, signed heads, inclusion proofs, streaming batches), replay tooling, consistency-token issuing, lease renewal, group kill
//! and attestation-gated blueprint admission.
//!
//! The verification side is [`crate::lease`], [`crate::blueprint`], [`crate::break_glass`], [`crate::fresh_at`] and [`crate::k3`]; shadow
//! rollout is [`crate::grants_shadow`], list-authorized [`crate::grants_list`], the management service and HTTP bindings
//! [`crate::grants_service`]. Records are `serde_json::Value`s; a secret is a 32-byte Ed25519 seed; a signer that refuses (the
//! reference throws) returns `Err`. Hooks are plain closures.
//!
//! Signer well-formedness: the verifiers' own shape checks are private to their modules, so a signer signs the body and then runs the
//! module's `verify_*` over the finished record. That is exactly "well formed AND signed over exactly these members", the check the
//! reference runs before signing.
use crate::agent::KeyPair;
use crate::attest::util::b64url_enc;
use crate::blueprint::{verify_blueprint, BlueprintRegistry, AGENT_BLUEPRINT_DOMAIN};
use crate::break_glass::{verify_break_glass, verify_break_glass_review, BREAK_GLASS_DOMAIN, BREAK_GLASS_REVIEW_DOMAIN};
use crate::fresh_at::{check_fresh_at, verify_body as verify_body_opt, verify_fresh_at, FreshAtState, FRESH_AT_DOMAIN};
use crate::k3::{bundle_shape_error, record_commit, BUNDLE_DOMAIN, LOG_HEAD_DOMAIN};
use crate::lease::{int, lease_cap, nat, pick, s, verify_lease, verify_lease_revocation, LeaseRegistry, LEASE_DOMAIN, LEASE_REVOKE_DOMAIN};
use crate::oauth::truthy;
use crate::{canonicalize_strict, hash_canonical_strict, merkle_root, safe_int};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;

const LEASE_KEYS: [&str; 14] = [
    "v",
    "lease_id",
    "path",
    "grant_ref",
    "holder",
    "requester",
    "approvers",
    "justification_digest",
    "seq",
    "issued_at",
    "renewed_at",
    "expires_at",
    "max_ttl",
    "authority",
];
const REV_KEYS: [&str; 5] = ["v", "target", "value", "revoked_at", "authority"];
const BP_KEYS: [&str; 11] = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator"];
const BG_KEYS: [&str; 11] =
    ["v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"];
const RV_KEYS: [&str; 6] = ["v", "id", "outcome", "notes_digest", "at", "reviewer"];
const FRESH_NUMERIC: [&str; 4] = ["revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"];
const FRESH_BODY_KEYS: [&str; 9] =
    ["v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer"];

// ---- JavaScript value helpers ------------------------------------------------------------------------------------------------

/// JavaScript object spread (`{...x}`): an object copies, an array or string spreads its indices, anything else adds nothing.
pub(crate) fn spread(x: &Value) -> Map<String, Value> {
    match x {
        Value::Object(m) => m.clone(),
        Value::Array(a) => a.iter().enumerate().map(|(i, v)| (i.to_string(), v.clone())).collect(),
        Value::String(t) => t.chars().enumerate().map(|(i, c)| (i.to_string(), Value::String(c.to_string()))).collect(),
        _ => Map::new(),
    }
}

/// `Object.entries` for the shapes a JSON value can take.
pub(crate) fn entries(x: &Value) -> Vec<(String, Value)> {
    spread(x).into_iter().collect()
}

/// `o` without the members in `drop` (an object; anything else is returned as is).
pub(crate) fn without(o: &Value, drop: &[&str]) -> Value {
    match o {
        Value::Object(m) => Value::Object(m.iter().filter(|(k, _)| !drop.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect()),
        other => other.clone(),
    }
}

/// `pick` that refuses when a member is missing (the reference indexes every listed member).
pub(crate) fn pick_all(v: &Value, keys: &[&str]) -> Result<Value, String> {
    let mut m = Map::new();
    for k in keys {
        match v.get(*k) {
            Some(x) => {
                m.insert((*k).to_string(), x.clone());
            }
            None => return Err(format!("missing member {k}")),
        }
    }
    Ok(Value::Object(m))
}

fn rank(v: Option<&Value>) -> Option<u8> {
    match v.and_then(Value::as_str) {
        Some("deny") => Some(0),
        Some("escalate") => Some(1),
        Some("allow") => Some(2),
        _ => None,
    }
}

/// `a > b` over decision kinds; false when either is not a kind.
pub(crate) fn gt(a: Option<u8>, b: Option<u8>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x > y)
}

pub(crate) fn rank_of(v: Option<&Value>) -> Option<u8> {
    rank(v)
}

/// Strings compared the way JavaScript compares them (UTF-16 code units).
pub(crate) fn u16key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

// ---- sig.ts -----------------------------------------------------------------------------------------------------------------

/// The b64u public key of a 32-byte Ed25519 seed.
pub fn signer_of(secret: &[u8; 32]) -> String {
    KeyPair::from_seed(secret).public
}

/// Domain-separated Ed25519 signature over strict-canonical JSON. Errs on a body outside the strict profile.
pub fn sign_body(domain: &str, body: &Value, secret: &[u8; 32]) -> Result<String, String> {
    let mut msg = domain.as_bytes().to_vec();
    msg.extend_from_slice(canonicalize_strict(body)?.as_bytes());
    Ok(b64url_enc(&KeyPair::from_seed(secret).sign(&msg)))
}

/// `sig` is a canonical signature by `signer` over `domain || strictCanonical(body)`. Never refuses by erroring: anything wrong is false.
pub fn verify_body(domain: &str, body: &Value, signer: &Value, sig: &Value) -> bool {
    match (signer.as_str(), sig.as_str()) {
        (Some(who), Some(g)) => verify_body_opt(domain, body, who, Some(g)),
        _ => false,
    }
}

// ---- signers ----------------------------------------------------------------------------------------------------------------

/// `{v: 1, ...rec, <who>: signer}`
fn with_signer(rec: &Value, who: &str, secret: &[u8; 32]) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("v".to_string(), json!(1));
    for (k, v) in spread(rec) {
        m.insert(k, v);
    }
    m.insert(who.to_string(), Value::String(signer_of(secret)));
    m
}

/// Sign the `keys` members of `base`, attach `sig`, and refuse unless `ok(record)` (the module's own verifier) accepts the result.
fn finish(base: Map<String, Value>, domain: &str, keys: &[&str], secret: &[u8; 32], msg: &str, ok: &dyn Fn(&Value) -> bool) -> Result<Value, String> {
    let base = Value::Object(base);
    let sig = sign_body(domain, &pick(&base, keys), secret).map_err(|e| format!("{msg} ({e})"))?;
    let mut rec = base;
    rec["sig"] = Value::String(sig);
    if !ok(&rec) {
        return Err(msg.to_string());
    }
    Ok(rec)
}

/// Sign a lease record. Refuses a malformed record or one that outlives `issued_at + max_ttl`.
pub fn sign_lease(secret: &[u8; 32], l: &Value) -> Result<Value, String> {
    finish(
        with_signer(l, "authority", secret),
        LEASE_DOMAIN,
        &LEASE_KEYS,
        secret,
        "signLease: a malformed lease, or one past issued_at + max_ttl",
        &|r: &Value| verify_lease(r) && int(r, "expires_at") <= lease_cap(r),
    )
}

/// Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it.
pub fn sign_lease_unsafe_over_cap(secret: &[u8; 32], l: &Value) -> Result<Value, String> {
    finish(with_signer(l, "authority", secret), LEASE_DOMAIN, &LEASE_KEYS, secret, "signLeaseUnsafeOverCap: malformed", &|r: &Value| verify_lease(r))
}

pub fn sign_lease_revocation(secret: &[u8; 32], r: &Value) -> Result<Value, String> {
    finish(with_signer(r, "authority", secret), LEASE_REVOKE_DOMAIN, &REV_KEYS, secret, "signLeaseRevocation: malformed", &|x: &Value| {
        verify_lease_revocation(x)
    })
}

/// Sign a blueprint record with the operator's secret.
pub fn sign_blueprint(secret: &[u8; 32], b: &Value) -> Result<Value, String> {
    finish(with_signer(b, "operator", secret), AGENT_BLUEPRINT_DOMAIN, &BP_KEYS, secret, "signBlueprint: a malformed blueprint", &|x: &Value| {
        verify_blueprint(x)
    })
}

pub fn sign_break_glass(secret: &[u8; 32], b: &Value) -> Result<Value, String> {
    finish(
        with_signer(b, "authority", secret),
        BREAK_GLASS_DOMAIN,
        &BG_KEYS,
        secret,
        "signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16",
        &|x: &Value| verify_break_glass(x),
    )
}

pub fn sign_break_glass_review(secret: &[u8; 32], r: &Value) -> Result<Value, String> {
    finish(with_signer(r, "reviewer", secret), BREAK_GLASS_REVIEW_DOMAIN, &RV_KEYS, secret, "signBreakGlassReview: malformed", &|x: &Value| {
        verify_break_glass_review(x)
    })
}

// ---- policy bundles ---------------------------------------------------------------------------------------------------------

/// One signer's signature over the bundle body: `{signer, sig}`. Collect k of them and call [`assemble_bundle`].
pub fn sign_bundle(body: &Value, secret: &[u8; 32]) -> Result<Value, String> {
    if let Some(e) = bundle_shape_error(body) {
        return Err(format!("signBundle: {e}"));
    }
    let sig = sign_body(BUNDLE_DOMAIN, &without(body, &["sigs"]), secret)?;
    Ok(json!({"signer": signer_of(secret), "sig": sig}))
}

/// The body with `sigs` replaced by the collected signatures.
pub fn assemble_bundle(body: &Value, sigs: &Value) -> Value {
    let mut m = spread(&without(body, &["sigs"]));
    m.insert("sigs".to_string(), sigs.clone());
    Value::Object(m)
}

// ---- decision records -------------------------------------------------------------------------------------------------------

/// Mask by data CLASS: every `detail` field whose class (from `classes`) is in `mask_classes` becomes a commitment.
pub fn mask_record(r: &Value, mask_classes: &[String]) -> Result<Value, String> {
    if !truthy(r.get("detail")) || !truthy(r.get("classes")) {
        return Ok(r.clone());
    }
    let classes = &r["classes"];
    let mut detail = Map::new();
    for (k, v) in entries(&r["detail"]) {
        let cls = classes.as_object().and_then(|c| c.get(&k)).and_then(Value::as_str);
        match cls {
            Some(c) if mask_classes.iter().any(|m| m == c) => {
                let h = hash_canonical_strict(&json!({"d": "atlas-pca/mask/v1", "k": k, "v": v})).ok_or("canonicalize: value outside the strict profile")?;
                detail.insert(k, Value::String(format!("masked:{c}:{h}")));
            }
            _ => {
                detail.insert(k, v);
            }
        }
    }
    let mut out = spread(r);
    out.insert("detail".to_string(), Value::Object(detail));
    Ok(Value::Object(out))
}

fn prove(hs: &[Vec<u8>], idx: usize, path: &mut Vec<Value>) {
    if hs.len() <= 1 {
        return;
    }
    let k = crate::split(hs.len() as u64) as usize;
    if idx < k {
        prove(&hs[..k], idx, path);
        path.push(json!({"side": "R", "hash": crate::b64_encode(&crate::build(&hs[k..]))}));
    } else {
        prove(&hs[k..], idx - k, path);
        path.push(json!({"side": "L", "hash": crate::b64_encode(&crate::build(&hs[..k]))}));
    }
}

/// RFC 6962 audit path of leaf `index`: `{index, size, path: [{side, hash}]}`. Errs on an index out of range.
pub fn merkle_proof(leaves: &[Value], index: &Value) -> Result<Value, String> {
    let idx = index.as_f64().filter(|f| f.fract() == 0.0 && *f >= 0.0 && *f < leaves.len() as f64).ok_or("merkleProof: index out of range")? as usize;
    let hs: Vec<Vec<u8>> = leaves.iter().map(crate::leaf_hash).collect::<Option<Vec<Vec<u8>>>>().ok_or("merkleProof: leaf outside the strict JSON profile")?;
    let mut path = Vec::new();
    prove(&hs, idx, &mut path);
    Ok(json!({"index": index, "size": leaves.len(), "path": path}))
}

/// Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs.
pub struct DecisionLog {
    secret: [u8; 32],
    mask: Vec<String>,
    recs: Vec<Value>,
}

impl DecisionLog {
    pub fn new(secret: [u8; 32], mask_classes: Vec<String>) -> Self {
        Self { secret, mask: mask_classes, recs: Vec::new() }
    }

    pub fn size(&self) -> usize {
        self.recs.len()
    }

    pub fn signer(&self) -> String {
        signer_of(&self.secret)
    }

    /// Mask, number and chain a record: `{v: 1, ...masked, seq, prev}`.
    pub fn append(&mut self, r: &Value) -> Result<Value, String> {
        let masked = mask_record(r, &self.mask)?;
        let prev = match self.recs.last() {
            Some(last) => record_commit(last).ok_or("canonicalize: record outside the strict profile")?,
            None => String::new(),
        };
        let mut m = Map::new();
        m.insert("v".to_string(), json!(1));
        for (k, v) in spread(&masked) {
            m.insert(k, v);
        }
        m.insert("seq".to_string(), json!(self.recs.len()));
        m.insert("prev".to_string(), Value::String(prev));
        let rec = Value::Object(m);
        self.recs.push(rec.clone());
        Ok(rec)
    }

    fn commits(&self) -> Result<Vec<Value>, String> {
        self.recs.iter().map(|r| record_commit(r).map(Value::String).ok_or_else(|| "canonicalize: record outside the strict profile".to_string())).collect()
    }

    /// The signed head at time `now`. Errs on an empty log (a Merkle tree needs a leaf).
    pub fn head(&self, now: &Value) -> Result<Value, String> {
        let commits = self.commits()?;
        let root = merkle_root(&commits)?;
        let last_commit = match commits.last() {
            Some(Value::String(c)) => c.clone(),
            _ => String::new(),
        };
        let base = json!({"v": 1, "size": self.recs.len(), "root": root, "last_commit": last_commit, "issued_at": now, "signer": self.signer()});
        let sig = sign_body(LOG_HEAD_DOMAIN, &base, &self.secret)?;
        let mut head = base;
        head["sig"] = Value::String(sig);
        Ok(head)
    }

    /// Inclusion proof of record `seq` under the current tree.
    pub fn proof(&self, seq: &Value) -> Result<Value, String> {
        merkle_proof(&self.commits()?, seq)
    }

    pub fn slice(&self, start: usize, end: usize) -> Vec<Value> {
        let end = end.min(self.recs.len());
        if start >= end {
            return Vec::new();
        }
        self.recs[start..end].to_vec()
    }
}

/// The next batch of at most `max` records starting at `from` (the stream cursor) with a freshly signed head.
pub fn next_batch(log: &DecisionLog, from: &Value, max: &Value, now: &Value) -> Result<Value, String> {
    let (f, m) = match (safe_int(from), safe_int(max)) {
        (Some(f), Some(m)) if f >= 0 && m >= 1 => (f as usize, m as usize),
        _ => return Err("nextBatch: bad cursor or size".to_string()),
    };
    let head = log.head(now)?;
    Ok(json!({"from": from, "records": log.slice(f, f.saturating_add(m)), "head": head}))
}

/// "What would have changed": re-run the pure decision function over recorded traffic under two revisions. `cases` is
/// `[{action_digest, input}]`; a decide hook returning `None` is JavaScript `undefined` (the member is left out of the entry).
pub fn semantic_diff(cases: &Value, old_decide: &dyn Fn(&Value) -> Option<Value>, new_decide: &dyn Fn(&Value) -> Option<Value>) -> Vec<Value> {
    let mut out = Vec::new();
    for c in cases.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let input = c.get("input").cloned().unwrap_or(Value::Null);
        let before = old_decide(&input);
        let after = new_decide(&input);
        if before != after {
            let mut e = Map::new();
            e.insert("action_digest".to_string(), c.get("action_digest").cloned().unwrap_or(Value::Null));
            if let Some(b) = &before {
                e.insert("before".to_string(), b.clone());
            }
            if let Some(a) = &after {
                e.insert("after".to_string(), a.clone());
            }
            let widened = gt(rank(after.as_ref()), rank(before.as_ref()));
            e.insert("direction".to_string(), json!(if widened { "widened" } else { "tightened" }));
            out.push(Value::Object(e));
        }
    }
    out
}

/// Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift).
pub fn audit_replay(records: &Value, cases: &Value, decide: &dyn Fn(&Value, &Value) -> Option<Value>) -> Vec<Value> {
    let mut by_action: HashMap<String, Value> = HashMap::new();
    for c in cases.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        if let Some(a) = c.get("action_digest").and_then(Value::as_str) {
            by_action.insert(a.to_string(), c.get("input").cloned().unwrap_or(Value::Null));
        }
    }
    let mut out = Vec::new();
    for r in records.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let Some(input) = r.get("action_digest").and_then(Value::as_str).and_then(|a| by_action.get(a)) else { continue };
        let got = decide(input, r.get("bundle_revision").unwrap_or(&Value::Null));
        if got.as_ref() != r.get("decision") {
            out.push(r.clone());
        }
    }
    out
}

// ---- consistency tokens (issuing side) --------------------------------------------------------------------------------------

/// Sign a `fresh_at` token for `scope` over `state` at `issued_at`. Refuses a malformed state.
pub fn sign_fresh_at(secret: &[u8; 32], scope: &Value, state: &Value, issued_at: &Value) -> Result<Value, String> {
    let ok = s(Some(scope), 256)
        && s(state.get("policy_digest"), 128)
        && FRESH_NUMERIC.iter().all(|k| nat(state.get(*k)).is_some())
        && nat(Some(issued_at)).is_some();
    if !ok {
        return Err("signFreshAt: a malformed state".to_string());
    }
    let mut m = Map::new();
    m.insert("v".to_string(), json!(1));
    m.insert("scope".to_string(), scope.clone());
    for (k, v) in spread(state) {
        m.insert(k, v);
    }
    m.insert("issued_at".to_string(), issued_at.clone());
    m.insert("signer".to_string(), Value::String(signer_of(secret)));
    let base = Value::Object(m);
    let sig = sign_body(FRESH_AT_DOMAIN, &pick_all(&base, &FRESH_BODY_KEYS)?, secret)?;
    let mut tok = base;
    tok["sig"] = Value::String(sig);
    Ok(tok)
}

/// Field-wise maximum of two states (the client-side fold). Equal revisions with different digests keep `a`'s digest.
pub fn merge_fresh_at(a: &Value, b: &Value) -> Result<Value, String> {
    let num = |v: &Value, k: &str| -> Result<f64, String> { v.get(k).and_then(Value::as_f64).ok_or_else(|| format!("mergeFreshAt: {k} is not a number")) };
    let mut m = Map::new();
    for k in FRESH_NUMERIC {
        let (x, y) = (num(a, k)?, num(b, k)?);
        m.insert(k.to_string(), if y > x { b[k].clone() } else { a[k].clone() });
    }
    let newer = num(b, "policy_revision")? > num(a, "policy_revision")?;
    let digest = if newer { b.get("policy_digest") } else { a.get("policy_digest") };
    m.insert("policy_digest".to_string(), digest.cloned().ok_or("mergeFreshAt: no policy_digest")?);
    Ok(Value::Object(m))
}

/// Compose a freshness verdict into a decision: it can only tighten (allow -> escalate/deny), never loosen.
pub fn gate_decision(decision: &str, v: &Value) -> String {
    let d = v.get("decision").and_then(Value::as_str);
    if decision == "deny" || d == Some("deny") {
        return "deny".to_string();
    }
    if d == Some("escalate") {
        return "escalate".to_string();
    }
    decision.to_string()
}

/// Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens.
pub struct FreshAtIssuer {
    secret: [u8; 32],
    scope: Value,
    state: Value,
}

impl FreshAtIssuer {
    pub fn new(secret: [u8; 32], scope: &Value, initial: &Value) -> Self {
        Self { secret, scope: scope.clone(), state: Value::Object(spread(initial)) }
    }

    pub fn current(&self) -> Value {
        self.state.clone()
    }

    /// Apply a write (any subset of counters; each only moves forward) and return its token. The state moves even when signing then refuses.
    pub fn advance(&mut self, patch: &Value, now: &Value) -> Result<Value, String> {
        let mut b = spread(&self.state);
        for (k, v) in spread(patch) {
            b.insert(k, v);
        }
        self.state = merge_fresh_at(&self.state, &Value::Object(b))?;
        sign_fresh_at(&self.secret, &self.scope, &self.state, now)
    }

    /// The `{decision: ok | escalate | deny, ...}` verdict of [`check_fresh_at`] against this issuer's state.
    pub fn check(&self, token: &Value, now: &Value, max_token_age_ms: Option<i64>) -> Value {
        let signer = signer_of(&self.secret);
        let bad = json!({"decision": "deny", "code": "bad_token"});
        if !verify_fresh_at(token, &signer) {
            return bad;
        }
        let (Some(local), Some(scope), Some(now)) = (FreshAtState::from_json(&self.state), self.scope.as_str(), safe_int(now)) else { return bad };
        check_fresh_at(token, &local, &signer, scope, now, max_token_age_ms).to_json()
    }
}

// ---- leases: renewal --------------------------------------------------------------------------------------------------------

/// Authority side: sign and register the next record of a lease. `veto(current) == true` refuses a renewal; it can never lengthen one.
/// Returns `{ok: true, record}` or `{ok: false, code}` (`bad_input`, `unknown_lease`, `vetoed`, `expired_lease`, or the registry's code).
#[allow(clippy::too_many_arguments)]
pub fn renew_lease(
    secret: &[u8; 32],
    reg: &LeaseRegistry,
    lease_id: &str,
    now: &Value,
    increment: &Value,
    justification_digest: &Value,
    approvers: Option<&Value>,
    veto: Option<&dyn Fn(&Value) -> bool>,
    chain: &[String],
) -> Value {
    let (Some(now_ms), Some(inc)) = (nat(Some(now)), nat(Some(increment))) else { return json!({"ok": false, "code": "bad_input"}) };
    if inc < 1 {
        return json!({"ok": false, "code": "bad_input"});
    }
    let cur = match reg.get(lease_id) {
        Ok(Some(c)) => c,
        Ok(None) => return json!({"ok": false, "code": "unknown_lease"}),
        Err(_) => return json!({"ok": false, "code": "store_unreachable"}),
    };
    if veto.is_some_and(|f| f(&cur)) {
        return json!({"ok": false, "code": "vetoed"});
    }
    let expires = (now_ms + inc).min(lease_cap(&cur));
    let mut next = spread(&without(&cur, &["v", "sig", "authority"]));
    next.insert("seq".to_string(), json!(int(&cur, "seq") + 1));
    next.insert("renewed_at".to_string(), now.clone());
    next.insert("expires_at".to_string(), json!(expires));
    next.insert("justification_digest".to_string(), justification_digest.clone());
    next.insert("approvers".to_string(), approvers.cloned().unwrap_or_else(|| cur.get("approvers").cloned().unwrap_or(Value::Null)));
    let record = match sign_lease(secret, &Value::Object(next)) {
        Ok(r) => r,
        Err(_) => return json!({"ok": false, "code": if expires <= now_ms { "expired_lease" } else { "bad_input" }}),
    };
    match reg.accept(&record, chain) {
        Ok(_) => json!({"ok": true, "record": record}),
        Err(code) => json!({"ok": false, "code": code}),
    }
}

// ---- blueprints: group kill and attestation-gated admission -------------------------------------------------------------------

/// GROUP KILL: the operator signs the blueprint as `disabled` at the next epoch; the registry accepts it and, given `revocation` (called
/// with `{kind: "issuer", value, reason, revokedAt}`), also revokes the blueprint key as an issuer; given `fresh_at` its
/// `revocation_epoch` advances to the record's epoch and the token is returned as `freshAt`. A refusal of the registry is
/// `{ok: false, code}`; a signing refusal is an `Err`.
pub fn group_kill(
    secret: &[u8; 32],
    reg: &BlueprintRegistry,
    key: &str,
    now: &Value,
    reason: Option<&str>,
    revocation: Option<&dyn Fn(&Value)>,
    fresh_at: Option<&mut FreshAtIssuer>,
) -> Result<Value, String> {
    let cur = match reg.get(key).map_err(|e| e.0)? {
        Some(c) => c,
        None => return Ok(json!({"ok": false, "code": "unknown_blueprint"})),
    };
    let mut next = spread(&without(&cur, &["sig", "operator", "v"]));
    next.insert("status".to_string(), json!("disabled"));
    next.insert("epoch".to_string(), json!(nat(cur.get("epoch")).unwrap_or(0) + 1));
    next.insert("issued_at".to_string(), now.clone());
    let record = sign_blueprint(secret, &Value::Object(next))?;
    if let Err(code) = reg.accept(&record) {
        return Ok(json!({"ok": false, "code": code}));
    }
    if let Some(hook) = revocation {
        hook(&json!({"kind": "issuer", "value": key, "reason": reason.unwrap_or("blueprint disabled (group kill)"), "revokedAt": now}));
    }
    let mut out = json!({"ok": true, "record": record});
    if let Some(f) = fresh_at {
        out["freshAt"] = f.advance(&json!({"revocation_epoch": record["epoch"]}), now)?;
    }
    Ok(out)
}

fn pin_matches(pin: &Value, ident: &Value) -> bool {
    let ents = entries(pin);
    !ents.is_empty() && ents.iter().all(|(k, v)| !v.is_null() && ident.as_object().is_some_and(|o| o.get(k) == Some(v)))
}

/// Admit from adapter evidence `{ok, bound, identity?, reason?}`: `ok` and `bound` must both be exactly `true`, and the identity the
/// adapter established must match one runtime pin. A hook that errs (the reference's thrown error; the text is its name) or a
/// malformed result denies.
pub fn admit_with_evidence(blueprint: &Value, get_evidence: &dyn Fn() -> Result<Value, String>) -> Value {
    let pins = match blueprint.get("runtime_pins").and_then(Value::as_array) {
        Some(p) if !p.is_empty() => p,
        _ => return json!({"admitted": false, "code": "no_pins"}),
    };
    let r = match get_evidence() {
        Ok(r) => r,
        Err(e) => return json!({"admitted": false, "code": "verifier_error", "reason": e}),
    };
    if r.get("ok") != Some(&Value::Bool(true)) {
        let mut o = json!({"admitted": false, "code": "not_ok"});
        if let Some(why) = r.get("reason").and_then(Value::as_str) {
            o["reason"] = json!(why);
        }
        return o;
    }
    if r.get("bound") != Some(&Value::Bool(true)) {
        return json!({"admitted": false, "code": "not_bound"});
    }
    let ident = match r.get("identity") {
        Some(i) if i.is_object() || i.is_array() => i,
        _ => return json!({"admitted": false, "code": "no_identity"}),
    };
    for p in pins {
        if pin_matches(p, ident) {
            return json!({"admitted": true, "identity": ident, "pin": p});
        }
    }
    json!({"admitted": false, "code": "no_matching_pin"})
}

/// Admit through a hardware attestation verifier: `verifier({document, ctx, nowMs, expected})` returns `{ok, bound, measured?, reason?}`.
/// No pins or no evidence is a denial.
pub fn admit_blueprint_instance(
    blueprint: &Value,
    document: Option<&Value>,
    verifier: &dyn Fn(&Value) -> Result<Value, String>,
    now_ms: &Value,
    ctx: &Value,
    expected: &Value,
) -> Value {
    let has_pins = blueprint.get("runtime_pins").and_then(Value::as_array).is_some_and(|p| !p.is_empty());
    if !has_pins {
        return json!({"admitted": false, "code": "no_pins"});
    }
    let Some(doc) = document.filter(|d| !d.is_null()) else { return json!({"admitted": false, "code": "not_ok", "reason": "no evidence"}) };
    let evidence = || -> Result<Value, String> {
        let h = verifier(&json!({"document": doc, "ctx": ctx, "nowMs": now_ms, "expected": expected}))?;
        let mut out = json!({"ok": h.get("ok") == Some(&Value::Bool(true)), "bound": h.get("bound") == Some(&Value::Bool(true))});
        if truthy(h.get("measured")) {
            out["identity"] = h["measured"].clone();
        }
        if let Some(why) = h.get("reason").and_then(Value::as_str) {
            out["reason"] = json!(why);
        }
        Ok(out)
    };
    admit_with_evidence(blueprint, &evidence)
}

/// Holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under; plug [`AdmissionRegistry::checker`] into
/// the blueprint check as `admitted`.
#[derive(Default)]
pub struct AdmissionRegistry {
    m: Mutex<HashMap<String, (Value, Value)>>,
}

impl AdmissionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn id(bp_key: &str, instance: &str) -> String {
        format!("{bp_key}\0{instance}")
    }

    pub fn admit(&self, instance_key: &str, bp: &Value, until: &Value) {
        let k = Self::id(bp.get("key").and_then(Value::as_str).unwrap_or(""), instance_key);
        self.m.lock().unwrap_or_else(|e| e.into_inner()).insert(k, (bp.get("epoch").cloned().unwrap_or(Value::Null), until.clone()));
    }

    pub fn revoke(&self, instance_key: &str, bp_key: &str) -> bool {
        self.m.lock().unwrap_or_else(|e| e.into_inner()).remove(&Self::id(bp_key, instance_key)).is_some()
    }

    /// Is `instance_key` admitted under the blueprint's CURRENT epoch and not past its `until`?
    pub fn check(&self, now: &Value, instance_key: &str, bp: &Value) -> bool {
        let k = Self::id(bp.get("key").and_then(Value::as_str).unwrap_or(""), instance_key);
        let m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        let Some((epoch, until)) = m.get(&k) else { return false };
        bp.get("epoch") == Some(epoch) && matches!((now.as_f64(), until.as_f64()), (Some(n), Some(u)) if n < u)
    }

    /// `admitted(instance, blueprint)` at time `now`, for [`crate::blueprint::check_blueprints_admitted`].
    pub fn checker<'a>(&'a self, now: Value) -> impl Fn(&str, &Value) -> bool + 'a {
        move |instance: &str, bp: &Value| self.check(&now, instance, bp)
    }
}
