//! Build provenance as a K1 discharge (track K9): a port of the TypeScript reference (provenance-gate.ts). The RFC 9162
//! inclusion check, the policy gates over [`provenance_gate`] facts (refusal codes and check order are normative, shared
//! through `conformance/provenance-vectors.json`) and the `needs_discharge` caveat a grant uses to ask an `artifact`
//! verifier for them. Provenance can only remove authority.
//!
//! Total: malformed input is `false` or a refusal code, never a panic.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::intent_strict::{bstr, closed_members, closed_members_error, nonneg, s, sint};

pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";
pub const INTOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

const MAX_SAFE: u64 = 9_007_199_254_740_991;

/// RFC 9162 section 2.1.1: the hash of a leaf, SHA-256(0x00 || data).
pub fn rfc9162_leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

fn node_hash(l: &[u8], r: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// RFC 9162 section 2.1.3.2: verify an inclusion proof of `leaf_hash` at `index` in a tree of `size` leaves with root `root`.
/// `proof` runs from the leaf level up, without the leaf and the root. Index and size are safe integers (64-bit arithmetic).
/// False on any malformed input.
pub fn verify_rfc9162_inclusion(leaf_hash: &[u8], index: u64, size: u64, proof: &[Vec<u8>], root: &[u8]) -> bool {
    if !(index <= MAX_SAFE && size <= MAX_SAFE && size >= 1 && index < size) {
        return false;
    }
    if leaf_hash.len() != 32 || root.len() != 32 || proof.len() > 64 || proof.iter().any(|p| p.len() != 32) {
        return false;
    }
    let (mut fnn, mut sn) = (index, size - 1);
    let mut r = [0u8; 32];
    r.copy_from_slice(leaf_hash);
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            r = node_hash(p, &r);
            if fnn & 1 == 0 {
                while fnn & 1 == 0 && fnn != 0 {
                    fnn >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && r[..] == root[..]
}

/// A non-empty string of at most 2048 UTF-8 bytes.
fn str2048(v: Option<&Value>) -> bool {
    bstr(v, 2048)
}

fn lower_hex(d: &str, n: usize) -> bool {
    d.len() == n && d.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn subject_error(v: Option<&Value>) -> bool {
    let Some(Value::Object(o)) = v else { return true };
    if !closed_members(o, &["alg", "digest"], &[]) {
        return true;
    }
    let n = match s(o.get("alg")) {
        Some("sha256") => 64,
        Some("sha512") => 128,
        _ => return true,
    };
    !s(o.get("digest")).is_some_and(|d| lower_hex(d, n))
}

/// `provenanceFactsError`: `None` when well-formed (closed members, bounded strings), else the reference's reason.
pub fn provenance_facts_error(f: &Value) -> Option<String> {
    let Some(o) = f.as_object() else { return Some("facts must be an object".into()) };
    if let Some(e) = closed_members_error(
        o,
        &["v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index"],
        &["source_repo", "source_ref", "source_digest", "provenance_source"],
        "facts",
    ) {
        return Some(e);
    }
    if sint(o.get("v")) != Some(1) {
        return Some("facts.v must be 1".into());
    }
    for k in ["predicate_type", "build_type", "builder_id", "identity", "oidc_issuer"] {
        if !str2048(o.get(k)) {
            return Some(format!("facts.{k} must be a non-empty string"));
        }
    }
    for k in ["source_repo", "source_ref", "source_digest"] {
        if o.get(k).is_some() && !str2048(o.get(k)) {
            return Some(format!("facts.{k} must be a non-empty string"));
        }
    }
    if !o.get("subjects").and_then(Value::as_array).is_some_and(|a| !a.is_empty() && a.len() <= 64 && !a.iter().any(|x| subject_error(Some(x)))) {
        return Some("facts.subjects must be 1..64 {alg, digest}".into());
    }
    if nonneg(o.get("integrated_time")).is_none() {
        return Some("facts.integrated_time must be a non-negative integer".into());
    }
    if nonneg(o.get("rekor_log_index")).is_none() {
        return Some("facts.rekor_log_index must be a non-negative integer".into());
    }
    if let Some(p) = o.get("provenance_source") {
        let ok = p.as_object().is_some_and(|p| {
            closed_members(p, &["uri"], &["git_commit"]) && str2048(p.get("uri")) && (p.get("git_commit").is_none() || str2048(p.get("git_commit")))
        });
        if !ok {
            return Some("facts.provenance_source is malformed".into());
        }
    }
    None
}

fn level_of(v: Option<&Value>) -> Option<i64> {
    sint(v).filter(|l| (1..=3).contains(l))
}

/// `provenancePolicyError`: `None` when well-formed, else the reference's reason.
pub fn provenance_policy_error(p: &Value) -> Option<String> {
    let Some(o) = p.as_object() else { return Some("policy must be an object".into()) };
    if let Some(e) = closed_members_error(o, &["roots", "min_level"], &["source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime"], "policy") {
        return Some(e);
    }
    let Some(roots) = o.get("roots").and_then(Value::as_array).filter(|a| !a.is_empty() && a.len() <= 32) else {
        return Some("policy.roots must hold 1..32 pairs".into());
    };
    for r in roots {
        let Some(r) = r.as_object().filter(|r| closed_members(r, &["oidc_issuer", "builder_id", "level"], &["identity", "identity_prefix"])) else {
            return Some("policy root is malformed".into());
        };
        if !str2048(r.get("oidc_issuer")) || !str2048(r.get("builder_id")) {
            return Some("policy root needs oidc_issuer and builder_id".into());
        }
        if r.get("identity").is_none() == r.get("identity_prefix").is_none() {
            return Some("policy root needs exactly one of identity and identity_prefix".into());
        }
        if r.get("identity").is_some() && !str2048(r.get("identity")) {
            return Some("policy root identity is malformed".into());
        }
        // a prefix must at least name a scheme and a host; the length is in UTF-16 code units, as the reference counts
        if r.get("identity_prefix").is_some() && !(str2048(r.get("identity_prefix")) && s(r.get("identity_prefix")).is_some_and(|x| x.encode_utf16().count() >= 10)) {
            return Some("policy root identity_prefix must be at least 10 characters".into());
        }
        if level_of(r.get("level")).is_none() {
            return Some("policy root level must be 1, 2 or 3".into());
        }
    }
    if level_of(o.get("min_level")).is_none() {
        return Some("policy.min_level must be 1, 2 or 3".into());
    }
    if o.get("source_repo").is_some() && !str2048(o.get("source_repo")) {
        return Some("policy.source_repo is malformed".into());
    }
    if o.get("source_ref").is_some() && o.get("source_ref_prefix").is_some() {
        return Some("policy takes source_ref or source_ref_prefix, not both".into());
    }
    if o.get("source_ref").is_some() && !str2048(o.get("source_ref")) {
        return Some("policy.source_ref is malformed".into());
    }
    if o.get("source_ref_prefix").is_some() && !str2048(o.get("source_ref_prefix")) {
        return Some("policy.source_ref_prefix is malformed".into());
    }
    if let Some(b) = o.get("build_types") {
        if !b.as_array().is_some_and(|a| !a.is_empty() && a.len() <= 16 && a.iter().all(|x| str2048(Some(x)))) {
            return Some("policy.build_types must hold 1..16 strings".into());
        }
    }
    if o.get("max_age_s").is_some() && !sint(o.get("max_age_s")).is_some_and(|x| x >= 1) {
        return Some("policy.max_age_s must be a positive integer".into());
    }
    if o.get("require_runtime").is_some_and(|v| !v.is_boolean()) {
        return Some("policy.require_runtime must be a boolean".into());
    }
    None
}

/// A passing [`provenance_gate`]: the SLSA level of the pinned pair and the claims an `artifact` discharge carries.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenanceGateOk {
    pub level: i64,
    pub claims: Map<String, Value>,
}

/// `provenanceGate({facts, policy, runtime?, now})`: the gates in the reference order; `Err` carries the refusal code
/// (`malformed_policy`, `malformed_facts`, `malformed_runtime`, `predicate_type`, `future`, `stale`, `no_root`, `level`,
/// `source_mismatch`, `source_repo`, `source_ref`, `build_type`, `runtime_required`, `runtime_mismatch`,
/// `subject_ambiguous`, `claim_too_long`). An absent member is absent; a JSON `null` is present (and malformed). Total.
pub fn provenance_gate(input: &Value) -> Result<ProvenanceGateOk, &'static str> {
    let Some(i) = input.as_object() else { return Err("malformed_facts") };
    let (facts, policy, runtime) = (i.get("facts").unwrap_or(&Value::Null), i.get("policy").unwrap_or(&Value::Null), i.get("runtime"));
    if provenance_policy_error(policy).is_some() {
        return Err("malformed_policy");
    }
    if provenance_facts_error(facts).is_some() {
        return Err("malformed_facts");
    }
    let Some(now) = nonneg(i.get("now")) else { return Err("malformed_facts") };
    if runtime.is_some() && subject_error(runtime) {
        return Err("malformed_runtime");
    }
    let (Some(f), Some(p)) = (facts.as_object(), policy.as_object()) else { return Err("malformed_facts") };
    let fs = |k: &str| s(f.get(k));
    let ps = |k: &str| s(p.get(k));
    if fs("predicate_type") != Some(SLSA_PROVENANCE_V1) {
        return Err("predicate_type");
    }
    let it = nonneg(f.get("integrated_time")).unwrap_or(0);
    if it > now {
        return Err("future");
    }
    if let Some(max) = sint(p.get("max_age_s")) {
        if now - it > max {
            return Err("stale");
        }
    }
    let (identity, builder_id, oidc_issuer) = (fs("identity").unwrap_or(""), fs("builder_id").unwrap_or(""), fs("oidc_issuer").unwrap_or(""));
    let mut level = 0;
    for r in p.get("roots").and_then(Value::as_array).into_iter().flatten() {
        if s(r.get("oidc_issuer")) != Some(oidc_issuer) || s(r.get("builder_id")) != Some(builder_id) {
            continue;
        }
        let hit = match s(r.get("identity")) {
            Some(x) => x == identity,
            None => s(r.get("identity_prefix")).is_some_and(|x| identity.starts_with(x)),
        };
        if !hit {
            continue;
        }
        level = level.max(sint(r.get("level")).unwrap_or(0));
    }
    if level == 0 {
        return Err("no_root");
    }
    if level < sint(p.get("min_level")).unwrap_or(4) {
        return Err("level");
    }
    if let Some(src) = f.get("provenance_source") {
        let (gc, sd) = (s(src.get("git_commit")), fs("source_digest"));
        if gc.is_some() && sd.is_some() && gc != sd {
            return Err("source_mismatch");
        }
        if let Some(repo) = fs("source_repo") {
            let uri = s(src.get("uri")).unwrap_or("");
            let base = format!("git+{repo}");
            if !(uri == base || uri.starts_with(&format!("{base}@"))) {
                return Err("source_mismatch");
            }
        }
    }
    if p.contains_key("source_repo") && fs("source_repo") != ps("source_repo") {
        return Err("source_repo");
    }
    if p.contains_key("source_ref") && fs("source_ref") != ps("source_ref") {
        return Err("source_ref");
    }
    if let Some(pre) = ps("source_ref_prefix") {
        if !fs("source_ref").is_some_and(|r| r.starts_with(pre)) {
            return Err("source_ref");
        }
    }
    if let Some(bt) = p.get("build_types").and_then(Value::as_array) {
        if !bt.iter().any(|b| s(Some(b)) == fs("build_type")) {
            return Err("build_type");
        }
    }
    let subjects: &[Value] = f.get("subjects").and_then(Value::as_array).map_or(&[], |a| a.as_slice());
    let (subject, bound) = match runtime {
        Some(rt) => match subjects.iter().find(|x| x.get("alg") == rt.get("alg") && x.get("digest") == rt.get("digest")) {
            Some(hit) => (hit, true),
            None => return Err("runtime_mismatch"),
        },
        None => {
            if p.get("require_runtime") == Some(&Value::Bool(true)) {
                return Err("runtime_required");
            }
            if subjects.len() != 1 {
                return Err("subject_ambiguous");
            }
            (&subjects[0], false)
        }
    };
    let mut claims = Map::new();
    claims.insert("subject_alg".into(), subject["alg"].clone());
    claims.insert("subject_digest".into(), subject["digest"].clone());
    claims.insert("slsa_level".into(), json!(level));
    for k in ["builder_id", "build_type", "oidc_issuer", "identity", "source_repo", "source_ref", "source_digest"] {
        if let Some(v) = f.get(k) {
            claims.insert(k.into(), v.clone());
        }
    }
    claims.insert("rekor_log_index".into(), json!(nonneg(f.get("rekor_log_index")).unwrap_or(0)));
    claims.insert("runtime_bound".into(), Value::Bool(bound));
    if claims.values().any(|v| v.as_str().is_some_and(|x| x.len() > 256)) {
        return Err("claim_too_long");
    }
    Ok(ProvenanceGateOk { level, claims })
}

/// Options of [`provenance_caveat`]; `None` takes the reference default.
#[derive(Debug, Clone, Default)]
pub struct ProvenanceCaveatOptions {
    /// Caveat id (K1 id syntax). Default `provenance`.
    pub id: Option<String>,
    /// Label of the verifier's `artifact` pin.
    pub issuer: String,
    /// 1, 2 or 3.
    pub min_level: i64,
    pub source_repo: Option<String>,
    /// Allowed builder ids (1..16), when given.
    pub builder_ids: Option<Vec<String>>,
    pub oidc_issuer: Option<String>,
    /// Require `runtime_bound: true`. Default true.
    pub require_runtime: Option<bool>,
    /// `chain_hop` or `action`. Default `action`.
    pub bind: Option<String>,
    /// Default 300 000 (5 minutes).
    pub ttl_ms: Option<i64>,
}

/// A `needs_discharge` caveat that asks the pinned `artifact` verifier for provenance claims.
pub fn provenance_caveat(o: &ProvenanceCaveatOptions) -> Value {
    let mut require = vec![json!({"claim": "slsa_level", "op": "gte", "value": o.min_level})];
    if let Some(r) = &o.source_repo {
        require.push(json!({"claim": "source_repo", "op": "eq", "value": r}));
    }
    if let Some(b) = &o.builder_ids {
        require.push(json!({"claim": "builder_id", "op": "in", "value": b}));
    }
    if let Some(i) = &o.oidc_issuer {
        require.push(json!({"claim": "oidc_issuer", "op": "eq", "value": i}));
    }
    if o.require_runtime != Some(false) {
        require.push(json!({"claim": "runtime_bound", "op": "eq", "value": true}));
    }
    json!({
        "type": "needs_discharge",
        "id": o.id.as_deref().unwrap_or("provenance"),
        "issuer": o.issuer,
        "issuer_class": "artifact",
        "bind": o.bind.as_deref().unwrap_or("action"),
        "ttl_ms": o.ttl_ms.unwrap_or(300_000),
        "require": require,
    })
}

