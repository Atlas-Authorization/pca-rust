//! Key rotation for PCA capability chains: rotate a leaf (agent) key, re-root a chain under a new principal key, revoke and
//! re-issue a compromised delegation subtree, and `apply_rotation` (write every revocation record to a registry atomically:
//! all or none). Every function returns the re-issued chain plus a revocation record `{capId?, holder?, issuer?, subtreeRoot?,
//! capIds, reason, revokedAt}` in the reference's shape. Caps are Ed25519 (the default suite), byte-identical to the reference.
use crate::agent::{delegate, mint_root, KeyPair, Suite};
use crate::oauth::spread;
use crate::revoke::{member, RevocationRegistry, RevocationStore};
use serde_json::{json, Map, Value};

const ED25519: Suite<'static> = Suite { alg: None, pq: None };

fn now_ms() -> Value {
    json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64))
}

fn nn<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    member(v, k).filter(|x| !x.is_null())
}

fn require_non_empty<'a>(chain: &'a Value, ctx: &str) -> Result<&'a Vec<Value>, String> {
    match chain {
        Value::Array(c) if !c.is_empty() => Ok(c),
        _ => Err(format!("{ctx}: empty chain")),
    }
}

/// `now` when given must be a finite number (null included: only an absent `now` defaults to the clock).
fn check_now(opts: &Value, ctx: &str) -> Result<Value, String> {
    match member(opts, "now") {
        None => Ok(now_ms()),
        Some(n) if n.is_number() => Ok(n.clone()),
        Some(_) => Err(format!("{ctx}: now must be a finite number")),
    }
}

fn reason(opts: &Value, default: &str) -> Value {
    nn(opts, "reason").cloned().unwrap_or_else(|| json!(default))
}

/// A hop the reference reads members of: `null` throws there.
fn hop<'a>(c: &'a Value, ctx: &str) -> Result<&'a Value, String> {
    if c.is_null() {
        Err(format!("{ctx}: malformed capability (null hop)"))
    } else {
        Ok(c)
    }
}

fn appended_caveats(parent: &Value, child: &Value) -> Result<Value, String> {
    let (Some(Value::Array(c)), Some(Value::Array(p))) = (member(child, "caveats"), member(parent, "caveats")) else {
        return Err("malformed capability: caveats must be arrays".into());
    };
    if c.len() < p.len() {
        return Err("malformed chain: a child carries fewer caveats than its parent (not an attenuation)".into());
    }
    Ok(Value::Array(c[p.len()..].to_vec()))
}

fn holder_str<'a>(c: &'a Value, ctx: &str) -> Result<&'a str, String> {
    member(c, "holder").and_then(Value::as_str).ok_or_else(|| format!("{ctx}: a capability holder must be a string"))
}

/// A record member, omitted when the source member is missing (`JSON.stringify` drops `undefined`).
fn put(m: &mut Map<String, Value>, k: &str, v: Option<&Value>) {
    if let Some(v) = v {
        m.insert(k.into(), v.clone());
    }
}

fn id_or_null(c: &Value) -> Value {
    member(c, "id").cloned().unwrap_or(Value::Null)
}

/// Rotate the LEAF holder's key: the leaf is re-signed by its issuer (`old_holder_secret`, the parent holder) to `new_key`,
/// with the leaf's own appended caveats. `opts` = `{reason?, now?}`. Returns `{chain, revocation}` (the old leaf revoked).
pub fn rotate_agent_key(chain: &Value, old_holder_secret: &KeyPair, new_key: &KeyPair, opts: &Value) -> Result<Value, String> {
    let ctx = "rotateAgentKey";
    let c = require_non_empty(chain, ctx)?;
    if c.len() < 2 {
        return Err("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey".into());
    }
    let parent = hop(&c[c.len() - 2], ctx)?;
    let leaf = hop(&c[c.len() - 1], ctx)?;
    if member(leaf, "issuer").and_then(Value::as_str) != Some(old_holder_secret.public.as_str()) {
        return Err(format!(
            "rotateAgentKey: oldHolderSecret (pub {}) is not the leaf's issuer {}; the leaf is re-signed by its parent holder (the leaf issuer)",
            old_holder_secret.public,
            member(leaf, "issuer").map_or_else(|| "undefined".into(), crate::oauth::js_str)
        ));
    }
    if member(leaf, "holder").and_then(Value::as_str) == Some(new_key.public.as_str()) {
        return Err("rotateAgentKey: newKeyPair is the key being rotated out".into());
    }
    let revoked_at = check_now(opts, ctx)?;
    let new_leaf = delegate(parent, old_holder_secret, Some(&new_key.public), &appended_caveats(parent, leaf)?, None, &ED25519)?;
    let mut out = c[..c.len() - 1].to_vec();
    out.push(new_leaf);
    let mut r = Map::new();
    put(&mut r, "capId", member(leaf, "id"));
    put(&mut r, "holder", member(leaf, "holder"));
    put(&mut r, "issuer", member(leaf, "issuer"));
    r.insert("capIds".into(), json!([id_or_null(leaf)]));
    r.insert("reason".into(), reason(opts, "agent key rotated"));
    r.insert("revokedAt".into(), revoked_at);
    Ok(json!({ "chain": out, "revocation": r }))
}

/// Re-root a chain under a new principal key. `args` = `{chain?, oldRoot?, reason?, now?}` (`chain ?? [oldRoot]`); every
/// non-root hop is re-signed by its issuer, `holder_secrets[i - 1]` for hop i. Returns `{chain, revocation}` (the whole old
/// chain revoked with the old root).
pub fn rotate_principal_key(args: &Value, old_principal_secret: &KeyPair, new_principal: &KeyPair, holder_secrets: &[KeyPair]) -> Result<Value, String> {
    let ctx = "rotatePrincipalKey";
    let built;
    let chain = match nn(args, "chain") {
        Some(c) => c,
        None => {
            built = match member(args, "oldRoot") {
                Some(r) if crate::oauth::truthy(Some(r)) => json!([r]),
                _ => json!([]),
            };
            &built
        }
    };
    let c = require_non_empty(chain, ctx)?;
    let old_root = hop(&c[0], ctx)?;
    if member(old_root, "parent").is_some() {
        return Err("rotatePrincipalKey: chain[0] is not a root (it has a parent)".into());
    }
    let root_issuer = member(old_root, "issuer").and_then(Value::as_str);
    if root_issuer != Some(old_principal_secret.public.as_str()) {
        return Err(format!("rotatePrincipalKey: oldPrincipalSecret (pub {}) is not the root's issuer", old_principal_secret.public));
    }
    if holder_secrets.len() != c.len() - 1 {
        return Err(format!("rotatePrincipalKey: expected {} holderSecrets (one per non-root hop), got {}", c.len() - 1, holder_secrets.len()));
    }
    if root_issuer == Some(new_principal.public.as_str()) {
        return Err("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out".into());
    }
    let revoked_at = check_now(args, ctx)?;
    let caveats = member(old_root, "caveats").ok_or("rotatePrincipalKey: the root has no caveats")?;
    let mut out = vec![mint_root(new_principal, holder_str(old_root, ctx)?, caveats, None, &ED25519)?];
    for i in 1..c.len() {
        let old_parent = hop(&c[i - 1], ctx)?;
        let old_child = hop(&c[i], ctx)?;
        let signer = &holder_secrets[i - 1];
        if member(old_child, "issuer").and_then(Value::as_str) != Some(signer.public.as_str()) {
            return Err(format!("rotatePrincipalKey: holderSecret for hop {i} (pub {}) is not that hop's issuer", signer.public));
        }
        let next = delegate(&out[i - 1], signer, Some(holder_str(old_child, ctx)?), &appended_caveats(old_parent, old_child)?, None, &ED25519)?;
        out.push(next);
    }
    let mut r = Map::new();
    put(&mut r, "capId", member(old_root, "id"));
    put(&mut r, "issuer", member(old_root, "issuer"));
    put(&mut r, "holder", member(old_root, "holder"));
    put(&mut r, "subtreeRoot", member(old_root, "id"));
    r.insert("capIds".into(), Value::Array(c.iter().map(id_or_null).collect()));
    r.insert("reason".into(), reason(args, "principal key rotated (re-root)"));
    r.insert("revokedAt".into(), revoked_at);
    Ok(json!({ "chain": out, "revocation": r }))
}

fn index_of_holder(c: &[Value], holder: &Value, ctx: &str) -> Result<Option<usize>, String> {
    for (i, h) in c.iter().enumerate() {
        if member(hop(h, ctx)?, "holder") == Some(holder) {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Treat `compromised_holder` as compromised: revoke the hop it first holds and every descendant, and re-delegate from the
/// safe ancestor (`ancestor_secret`, the holder just above) straight to `new_key`, carrying the old leaf's appended caveats
/// (never wider). `opts` = `{reason?, now?}`. Returns `{chain, revocation}`.
pub fn revoke_and_reissue_subtree(
    chain: &Value,
    compromised_holder: &Value,
    new_key: &KeyPair,
    ancestor_secret: &KeyPair,
    opts: &Value,
) -> Result<Value, String> {
    let ctx = "revokeAndReissueSubtree";
    let c = require_non_empty(chain, ctx)?;
    let Some(idx) = index_of_holder(c, compromised_holder, ctx)? else {
        return Err(format!("revokeAndReissueSubtree: holder {} is not in the chain", crate::oauth::js_str(compromised_holder)));
    };
    if idx == 0 {
        return Err(
            "revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey".into(),
        );
    }
    let ancestor = hop(&c[idx - 1], ctx)?;
    let subtree_root = &c[idx];
    let leaf = hop(&c[c.len() - 1], ctx)?;
    if member(ancestor, "holder").and_then(Value::as_str) != Some(ancestor_secret.public.as_str()) {
        return Err(format!("revokeAndReissueSubtree: ancestorSecret (pub {}) is not the safe ancestor's holder", ancestor_secret.public));
    }
    for h in &c[idx..] {
        if member(hop(h, ctx)?, "holder").and_then(Value::as_str) == Some(new_key.public.as_str()) {
            return Err("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree".into());
        }
    }
    let revoked_at = check_now(opts, ctx)?;
    let new_hop = delegate(ancestor, ancestor_secret, Some(&new_key.public), &appended_caveats(ancestor, leaf)?, None, &ED25519)?;
    let mut out = c[..idx].to_vec();
    out.push(new_hop);
    let mut r = Map::new();
    put(&mut r, "capId", member(subtree_root, "id"));
    r.insert("holder".into(), compromised_holder.clone());
    put(&mut r, "issuer", member(subtree_root, "issuer"));
    put(&mut r, "subtreeRoot", member(subtree_root, "id"));
    r.insert("capIds".into(), Value::Array(c[idx..].iter().map(id_or_null).collect()));
    r.insert("reason".into(), reason(opts, "delegation subtree compromised"));
    r.insert("revokedAt".into(), revoked_at);
    Ok(json!({ "chain": out, "revocation": r }))
}

/// [`revoke_and_reissue_subtree`] end to end: one revocation record per revoked hop (each naming the subtree root) plus the
/// re-issued chain, `{revocations, reissued}`.
pub fn compromised_key_flow(chain: &Value, compromised_holder: &Value, new_key: &KeyPair, ancestor_secret: &KeyPair, opts: &Value) -> Result<Value, String> {
    let ctx = "compromisedKeyFlow";
    let c = require_non_empty(chain, ctx)?;
    let Some(idx) = index_of_holder(c, compromised_holder, ctx)? else {
        return Err(format!("compromisedKeyFlow: holder {} is not in the chain", crate::oauth::js_str(compromised_holder)));
    };
    let reissued = revoke_and_reissue_subtree(chain, compromised_holder, new_key, ancestor_secret, opts)?["chain"].take();
    let root_id = member(&c[idx], "id");
    let revoked_at = check_now(opts, ctx)?;
    let why = reason(opts, "delegation subtree compromised");
    let revocations: Vec<Value> = c[idx..]
        .iter()
        .map(|h| {
            let mut r = Map::new();
            put(&mut r, "capId", member(h, "id"));
            put(&mut r, "holder", member(h, "holder"));
            put(&mut r, "issuer", member(h, "issuer"));
            put(&mut r, "subtreeRoot", root_id);
            r.insert("capIds".into(), json!([id_or_null(h)]));
            r.insert("reason".into(), why.clone());
            r.insert("revokedAt".into(), revoked_at.clone());
            Value::Object(r)
        })
        .collect();
    Ok(json!({ "revocations": revocations, "reissued": reissued }))
}

/// Where [`apply_rotation`] writes: a revocation registry (or anything with its `revoke` / `unrevoke` / `lookup`).
pub trait RevocationSink {
    fn revoke(&self, input: &Value) -> Result<(), String>;
    fn unrevoke(&self, key: &Value) -> Result<bool, String>;
    fn lookup(&self, kind: &str, value: &str) -> Result<Option<Value>, String>;
}

impl<S: RevocationStore> RevocationSink for RevocationRegistry<S> {
    fn revoke(&self, input: &Value) -> Result<(), String> {
        RevocationRegistry::revoke(self, input).map(|_| ())
    }
    fn unrevoke(&self, key: &Value) -> Result<bool, String> {
        RevocationRegistry::unrevoke(self, key)
    }
    fn lookup(&self, kind: &str, value: &str) -> Result<Option<Value>, String> {
        RevocationRegistry::lookup(self, kind, value)
    }
}

/// Write the cap ids of one record or an array of records (`capIds ?? [capId]`, first record wins per id) to `sink`, all or
/// none: on a failure every id this call newly added is unrevoked again (best effort) and the failure returned. Refuses an
/// invalid id, an empty set, and a `reissued` chain that still contains a revoked cap. Returns the ids in order.
pub fn apply_rotation(sink: &dyn RevocationSink, records: &Value, reissued: Option<&Value>) -> Result<Vec<String>, String> {
    let list = match records {
        Value::Array(a) => a.clone(),
        r => vec![r.clone()],
    };
    let mut todo: Vec<(String, Value)> = Vec::new();
    for r in &list {
        if r.is_null() {
            return Err("applyRotation: a record is null".into());
        }
        let ids = match nn(r, "capIds") {
            Some(ids) => spread(ids, "capIds")?,
            None => member(r, "capId").map_or_else(Vec::new, |id| vec![id.clone()]),
        };
        for id in ids {
            let Some(s) = id.as_str().filter(|s| !s.is_empty()) else {
                return Err("applyRotation: a record names an invalid capability id".into());
            };
            if !todo.iter().any(|(k, _)| k == s) {
                todo.push((s.to_string(), r.clone()));
            }
        }
    }
    if todo.is_empty() {
        return Err("applyRotation: the record names no capability to revoke".into());
    }
    let kept: Vec<Value> = match reissued.filter(|r| !r.is_null()) {
        None => Vec::new(),
        Some(Value::Array(a)) => {
            a.iter().map(|c| hop(c, "applyRotation").map(|c| member(c, "id").cloned().unwrap_or(Value::Null))).collect::<Result<_, _>>()?
        }
        Some(_) => return Err("applyRotation: reissued must be a capability chain".into()),
    };
    if todo.iter().any(|(id, _)| kept.contains(&json!(id))) {
        return Err("applyRotation: the re-issued chain contains a capability that is being revoked".into());
    }
    let mut added: Vec<String> = Vec::new();
    for (id, r) in &todo {
        if let Err(e) = write_one(sink, id, r, &mut added) {
            for id in &added {
                let _ = sink.unrevoke(&json!({ "kind": "cap", "value": id })); // best effort: the original failure is the one to report
            }
            return Err(e);
        }
    }
    Ok(todo.into_iter().map(|(id, _)| id).collect())
}

fn write_one(sink: &dyn RevocationSink, id: &str, r: &Value, added: &mut Vec<String>) -> Result<(), String> {
    if sink.lookup("cap", id)?.is_none() {
        added.push(id.to_string());
    }
    let mut input = Map::new();
    input.insert("kind".into(), json!("cap"));
    input.insert("value".into(), json!(id));
    put(&mut input, "reason", member(r, "reason"));
    put(&mut input, "revokedAt", member(r, "revokedAt"));
    sink.revoke(&Value::Object(input))
}
