//! The remaining agent-side and principal-side signers, byte-identical to the TypeScript reference for the same keys and inputs:
//! threshold shares, the PQ key binding, caution claims, lease heartbeats, read receipts, mesh actions, intent session roots and
//! session grants, action schemas, intent-required questions, progress steps, label receipts, oracle facts, policy templates and tighten overlays, revocation epochs,
//! constitutions and signed safety evidence. Each runs the shape checks the reference runs before (and where it has one, after)
//! signing, and refuses a suite this crate cannot sign with `unsupported_suite: <alg>`.

use crate::agent::{mint_root, sign_artifact, sign_with_suite, KeyPair, Suite};
use crate::{canonicalize_strict, hash_canonical_strict, serde_json::json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value};

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn strict_msg(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    let mut m = domain.as_bytes().to_vec();
    m.extend(canonicalize_strict(body)?.into_bytes());
    Ok(m)
}

/// `utf8(domain) || sha256(utf8(id))`: the message of the content-addressed artifacts (constitution, evidence, template, overlay).
fn id_msg(domain: &str, id: &str) -> Vec<u8> {
    let mut m = domain.as_bytes().to_vec();
    m.extend(crate::sha(id.as_bytes()));
    m
}

fn is_safe_int(v: &Value) -> bool {
    v.as_f64().is_some_and(|f| f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0) && v.is_number()
}

fn obj<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object().ok_or_else(|| format!("{what}: not an object"))
}

// ---- threshold shares -----------------------------------------------------------------------------------------------------

const SHARE_ROLES: [&str; 3] = ["agent", "guardian", "principal"];

/// The bytes a role's share signs: `"atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t` plus, for a non-ed25519
/// suite, `"\0atlas-pca/share-suite/v1\0" || alg` (so a PQ share cannot be stripped back to ed25519).
pub fn share_message(role: &str, message: &[u8], signer_set: &[Value], t: i64, alg: Option<&str>) -> Result<Vec<u8>, String> {
    if !(1..=3).contains(&t) {
        return Err("shareMessage: t must be 1, 2 or 3".into());
    }
    let mut m = format!("atlas-pca/share/{role}\0").into_bytes();
    m.extend(crate::sha(message));
    m.extend(crate::signer_set_hash(signer_set).ok_or("shareMessage: malformed signer set")?);
    m.push(t as u8);
    if let Some(a) = alg.filter(|a| *a != "ed25519" && crate::REGISTERED_SUITES.contains(a)) {
        m.extend(format!("\0atlas-pca/share-suite/v1\0{a}").into_bytes());
    }
    Ok(m)
}

/// A role's explicit threshold share `{role, publicKey, sig, alg?, pq_sig?}` over [`share_message`] for the signer set and `t` it
/// is for (`message` is the PCActn's threshold message). Under a PQ suite the role's PQ key must be the set's `pq_pk` for it.
pub fn sign_threshold_share(role: &str, key: &KeyPair, message: &[u8], signer_set: &[Value], t: i64, s: &Suite) -> Result<Value, String> {
    sign_prepared_share(role, key, &share_message(role, message, signer_set, t, s.alg)?, s)
}

/// Sign already-computed share bytes (the `share_message` a step-up hands a principal device).
pub fn sign_prepared_share(role: &str, key: &KeyPair, prepared: &[u8], s: &Suite) -> Result<Value, String> {
    if !SHARE_ROLES.contains(&role) {
        return Err(format!("signPreparedShare: unknown role '{role}'"));
    }
    let alg = s.alg.unwrap_or("ed25519");
    if !crate::REGISTERED_SUITES.contains(&alg) {
        return Err(format!("signPreparedShare: unknown signature alg '{alg}'"));
    }
    let (sig, pq_sig) = sign_with_suite(s, Some(key), prepared)?;
    let mut m = json!({"role": role, "publicKey": key.public, "sig": sig});
    if alg != "ed25519" {
        m["alg"] = json!(alg);
    }
    if let Some(p) = pq_sig {
        m["pq_sig"] = json!(p);
    }
    Ok(m)
}

// ---- PQ key binding -------------------------------------------------------------------------------------------------------

/// The identity's signed statement "this PQ key is mine, as of `epoch`, for audience `aud`" `{ed, pq, epoch, aud, sig}` (Ed25519
/// over `"atlas-pca/pq-binding/v2\0" || ed \0 pq \0 epoch \0 aud`). `epoch` is a positive safe integer the identity raises on
/// every rotation.
pub fn sign_pq_binding(ed: &KeyPair, pq_public: &str, epoch: i64, aud: &str) -> Result<Value, String> {
    if !(1..=9_007_199_254_740_991).contains(&epoch) {
        return Err("signPqBinding: epoch must be a positive safe integer".into());
    }
    if aud.is_empty() {
        return Err("signPqBinding: aud (the instance/audience id) is required".into());
    }
    let mut m = b"atlas-pca/pq-binding/v2\0".to_vec();
    m.extend(format!("{}\0{pq_public}\0{epoch}\0{aud}", ed.public).into_bytes());
    Ok(json!({"ed": ed.public, "pq": pq_public, "epoch": epoch, "aud": aud, "sig": b64(&ed.sign(&m))}))
}

// ---- caution, lease heartbeat ---------------------------------------------------------------------------------------------

/// `canonicalBytes({d, b})`: the message of the agent-native artifacts.
fn native_msg(domain: &str, body: &Value) -> Result<Vec<u8>, String> {
    Ok(canonicalize_strict(&json!({"d": domain, "b": body}))?.into_bytes())
}

fn caution_body_error(b: &Value) -> Option<&'static str> {
    let Some(o) = b.as_object() else { return Some("not an object") };
    let ne = |k: &str| o.get(k).and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if !ne("action_digest") {
        return Some("action_digest required");
    }
    if !ne("holder") {
        return Some("holder required");
    }
    if !o.get("caution").filter(|v| v.is_number()).and_then(Value::as_f64).is_some_and(|c| (0.0..=1.0).contains(&c)) {
        return Some("caution must be a finite number in [0,1]");
    }
    if let Some(r) = o.get("reason") {
        let ok = r.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)));
        if !ok {
            return Some("invalid reason");
        }
    }
    None
}

/// The holder's signed uncertainty about one action `{action_digest, caution, holder, reason?, sig}` (`caution` in [0, 1];
/// `reason` at most 64 characters of `[A-Za-z0-9_.:-]`). Other members of `body` are not signed.
pub fn sign_caution(holder: &KeyPair, body: &Value) -> Result<Value, String> {
    if let Some(e) = caution_body_error(body) {
        return Err(format!("signCaution: {e}"));
    }
    let mut clean = json!({"action_digest": body["action_digest"], "caution": body["caution"], "holder": body["holder"]});
    if let Some(r) = body.get("reason") {
        clean["reason"] = r.clone();
    }
    let sig = b64(&holder.sign(&native_msg("atlas-pca/caution/v1", &clean)?));
    clean["sig"] = json!(sig);
    Ok(clean)
}

/// The lease holder's signed heartbeat `{cap_id, seq, at, holder, lease_issued_at, sig}` (only those members of `body` are signed).
pub fn sign_heartbeat(holder: &KeyPair, body: &Value) -> Result<Value, String> {
    let g = |k: &str| body.get(k).cloned().ok_or_else(|| format!("signHeartbeat: {k} required"));
    let mut clean = json!({"cap_id": g("cap_id")?, "seq": g("seq")?, "at": g("at")?, "holder": g("holder")?, "lease_issued_at": g("lease_issued_at")?});
    let sig = b64(&holder.sign(&native_msg("atlas-pca/lease-hb/v2", &clean)?));
    clean["sig"] = json!(sig);
    Ok(clean)
}

// ---- read receipt (resource server) ---------------------------------------------------------------------------------------

/// The resource server's signed receipt for one read under `grant_body`: the fields it released and their labels, chained to
/// `prev` (the previous receipt of the grant).
#[allow(clippy::too_many_arguments)]
pub fn sign_read_receipt(rs: &KeyPair, grant_body: &Value, verb: &str, resource: &str, purpose: &str, fields: &Value, labels: &Value, issued_at: i64, prev: Option<&Value>) -> Result<Value, String> {
    let grant = crate::readside::read_grant_digest(grant_body).ok_or("signReadReceipt: the grant body is outside the strict JSON profile")?;
    let (seq, pref) = match prev {
        Some(p) => (p.get("seq").and_then(Value::as_i64).ok_or("signReadReceipt: the previous receipt has no seq")? + 1, json!(crate::readside::read_receipt_ref(p).ok_or("signReadReceipt: malformed previous receipt")?)),
        None => (0, Value::Null),
    };
    let mut body = json!({"v": 1, "grant": grant, "verb": verb, "resource": resource, "purpose": purpose, "seq": seq, "prev": pref,
        "fields": fields, "labels": labels, "issued_at": issued_at, "signer": rs.public});
    let sig = b64(&rs.sign(&strict_msg(crate::readside::READ_RECEIPT_DOMAIN, &body)?));
    body["sig"] = json!(sig);
    Ok(body)
}

// ---- mesh ------------------------------------------------------------------------------------------------------------------

/// The leaf holder's signature over the action bound to the chain tip: `"atlas-pca/mesh-action/v1\0" || canonical({action, tip})`.
pub fn sign_mesh_action(chain: &[Value], action: &Value, leaf: &KeyPair) -> Result<String, String> {
    let tip = crate::cap_hash(chain.last().ok_or("signMeshAction: empty chain")?);
    Ok(b64(&leaf.sign(&strict_msg("atlas-pca/mesh-action/v1\0", &json!({"action": action, "tip": tip}))?)))
}

/// A compact mesh proof: hops issued against the same head share one head entry (their cosignatures merged by witness) and
/// identical revocation bracketing leaves are carried once. `hops` are `{domain, head: {head, sig, cosigs}, inclusion,
/// revocation: {cap, issuer_key}, binding?}`; `pin_proofs` is carried when non-empty.
pub fn assemble_mesh_proof(chain: &[Value], hops: &[Value], action: &Value, leaf: &KeyPair, pin_proofs: Option<&[Value]>) -> Result<Value, String> {
    let mut heads: Vec<Value> = vec![];
    let mut head_keys: Vec<String> = vec![];
    let mut leaves: Vec<Value> = vec![];
    let mut leaf_keys: Vec<String> = vec![];
    let mut leaf_idx = |l: &Value| -> usize {
        // canonical: the same leaf in any member order is one entry (as the reference keys it)
        let k = crate::canonicalize(l);
        match leaf_keys.iter().position(|x| *x == k) {
            Some(i) => i,
            None => {
                leaves.push(l.clone());
                leaf_keys.push(k);
                leaves.len() - 1
            }
        }
    };
    let mut out_hops = vec![];
    for ev in hops {
        let h = ev.get("head").and_then(Value::as_object).ok_or("assembleMeshProof: hop head missing")?;
        let sig = h.get("sig").and_then(Value::as_str).ok_or("assembleMeshProof: hop head sig missing")?;
        let cosigs = h.get("cosigs").and_then(Value::as_array).ok_or("assembleMeshProof: hop head cosigs missing")?;
        let k = format!("{sig}|{}", crate::canonicalize(h.get("head").unwrap_or(&Value::Null)));
        let i = match head_keys.iter().position(|x| *x == k) {
            Some(i) => {
                let have: Vec<Value> = heads[i]["cosigs"].as_array().map_or(vec![], |c| c.iter().map(|c| c["witness"].clone()).collect());
                let add: Vec<Value> = cosigs.iter().filter(|c| !have.contains(&c["witness"])).cloned().collect();
                if let Some(a) = heads[i]["cosigs"].as_array_mut() {
                    a.extend(add);
                }
                i
            }
            None => {
                heads.push(json!({"head": h.get("head").cloned().unwrap_or(Value::Null), "sig": sig, "cosigs": cosigs}));
                head_keys.push(k);
                heads.len() - 1
            }
        };
        let rev = ev.get("revocation").ok_or("assembleMeshProof: hop revocation missing")?;
        let mut compact = |n: &Value| -> Value {
            let mut c = json!({"size": n.get("size").cloned().unwrap_or(Value::Null)});
            for side in ["lo", "hi"] {
                if let Some(l) = n.get(side).filter(|l| crate::mesh::truthy(l)) {
                    c[side] = json!(leaf_idx(l));
                }
            }
            c
        };
        let rc = compact(rev.get("cap").ok_or("assembleMeshProof: hop revocation.cap missing")?);
        let ri = compact(rev.get("issuer_key").ok_or("assembleMeshProof: hop revocation.issuer_key missing")?);
        let mut o = json!({"domain": ev.get("domain").cloned().unwrap_or(Value::Null), "head": i, "inclusion": ev.get("inclusion").cloned().unwrap_or(Value::Null),
            "revocation": {"cap": rc, "issuer_key": ri}});
        if let Some(b) = ev.get("binding").filter(|b| crate::mesh::truthy(b)) {
            o["binding"] = b.clone();
        }
        out_hops.push(o);
    }
    let mut proof = json!({"chain": chain, "heads": heads, "rev_leaves": leaves, "hops": out_hops, "action": action,
        "action_sig": sign_mesh_action(chain, action, leaf)?});
    if let Some(p) = pin_proofs.filter(|p| !p.is_empty()) {
        proof["pin_proofs"] = json!(p);
    }
    Ok(proof)
}

// ---- intent sessions -------------------------------------------------------------------------------------------------------

const SESSION_BODY_KEYS: [&str; 13] = ["v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors", "question_uri", "revocation", "flows", "expires_at"];

/// Sign a session root as one of its principals: the body (its 13 members) plus `signer` and the bound suite fields, under
/// `"atlas-pca/intent-session/v1\0"`. The result must pass the verifier's own shape check.
pub fn sign_session_root(principal: &KeyPair, body: &Value, s: &Suite) -> Result<Value, String> {
    let b = body.as_object().ok_or("signSessionRoot: session root is not an object")?;
    if let Some(k) = b.keys().find(|k| !SESSION_BODY_KEYS.contains(&k.as_str())) {
        return Err(format!("signSessionRoot: session root: unknown member '{k}'"));
    }
    let listed = b.get("principals").and_then(Value::as_array).is_some_and(|ps| ps.iter().any(|p| p.get("key").and_then(Value::as_str) == Some(principal.public.as_str())));
    if !listed {
        return Err("signSessionRoot: the signer is not one of the session principals".into());
    }
    let mut base = Map::new();
    for k in SESSION_BODY_KEYS {
        if let Some(v) = b.get(k) {
            base.insert(k.into(), v.clone());
        }
    }
    base.insert("signer".into(), json!(principal.public));
    let root = sign_artifact(crate::intent_session::INTENT_SESSION_SIG_DOMAIN, &Value::Object(base), principal, s)?;
    if let Some(e) = crate::session_root_shape_error(&root) {
        return Err(format!("signSessionRoot: {e}"));
    }
    Ok(root)
}

/// Inputs of [`mint_session_grant`] (G_0 at seq 0, or the delta grant D_k).
pub struct SessionGrantInput<'a> {
    pub principal: &'a KeyPair,
    pub holder: &'a str,
    pub holder_pq: Option<&'a str>,
    pub session: &'a str,
    pub seq: i64,
    /// The id of D_{k-1} (or G_0); required iff seq > 0.
    pub prev: Option<&'a str>,
    /// `session_root_digest(S)`.
    pub root: &'a str,
    /// The task-map digest (the map commitment when `map_form` is "commit").
    pub map_digest: &'a str,
    pub map_form: Option<&'a str>,
    pub predicates: &'a Value,
    pub caveats: Option<&'a Value>,
    pub agent_binding: Option<&'a Value>,
    pub risk_policy: Option<&'a Value>,
    /// b64u goal salt; random when `None`.
    pub salt: Option<&'a str>,
    pub suite: Suite<'a>,
}

/// Mint G_0 / D_k: a principal-signed root capability whose caveats are the envelope (goal `pca-intent:v2:<session>:<map>`, or
/// `pca-intent:v2c:` over a committed map) and the `intent_session` caveat. Returns `(grant, goal_salt)`.
pub fn mint_session_grant(a: &SessionGrantInput) -> Result<(Value, String), String> {
    let mut sc = json!({"type": "intent_session", "session": a.session, "seq": a.seq, "root": a.root});
    if let Some(p) = a.prev {
        sc["prev"] = json!(p);
    }
    if let Some(e) = crate::intent_session_caveat_error(Some(&sc)) {
        return Err(format!("mintSessionGrant: {e}"));
    }
    if !crate::workflow::is_b32_str(a.map_digest) {
        return Err("mintSessionGrant: mapDigest must be canonical base64url (32 bytes)".into());
    }
    let salt = match a.salt {
        Some(s) => s.to_string(),
        None => b64(&crate::agent::rand_bytes::<16>()?),
    };
    let prefix = if a.map_form == Some("commit") { "pca-intent:v2c:" } else { "pca-intent:v2:" };
    let goal = format!("{prefix}{}:{}", a.session, a.map_digest);
    let env = json!({"type": "envelope", "goal_commit": crate::agent::goal_commit_of(&goal, &salt)?, "predicates": a.predicates,
        "caveats": a.caveats.cloned().unwrap_or_else(|| json!([])), "agent_binding": a.agent_binding.cloned().unwrap_or_else(|| json!({})),
        "risk_policy": a.risk_policy.cloned().unwrap_or_else(crate::agent::default_risk_policy)});
    let grant = mint_root(a.principal, a.holder, &json!([env, sc]), a.holder_pq, &a.suite)?;
    Ok((grant, salt))
}

// ---- site and oracle artifacts ---------------------------------------------------------------------------------------------

fn site_sig(alg: &str, kid: &str, sig: String, pq_sig: Option<String>) -> Value {
    let mut s = json!({"alg": alg, "kid": kid, "value": sig});
    if let Some(p) = pq_sig {
        s["pq_value"] = json!(p);
    }
    s
}

/// Sign an action schema as the site: `sig = {alg, kid, value, pq_value?}` over `"atlas-pca/action-schema/v1\0" ||
/// strictCanonical(doc)` (`kid` names the site's discovery key). The unsigned document must be well formed.
pub fn sign_action_schema(doc: &Value, kid: &str, site: &KeyPair, s: &Suite) -> Result<Value, String> {
    if let Some(e) = crate::action_schema_shape_error_unsigned(doc) {
        return Err(format!("signActionSchema: {e}"));
    }
    let alg = s.alg.unwrap_or("ed25519");
    let (sig, pq_sig) = sign_with_suite(s, Some(site), &strict_msg(crate::action_schema::ACTION_SCHEMA_DOMAIN, doc)?)?;
    let mut out = doc.clone();
    out["sig"] = site_sig(alg, kid, sig, pq_sig);
    if let Some(e) = crate::action_schema_shape_error(&out) {
        return Err(format!("signActionSchema: {e}"));
    }
    Ok(out)
}

const INTENT_REQUIRED_DOMAIN: &str = "atlas-pca/intent-required/v1\0";
const INTENT_REQUIRED_KEYS: [&str; 13] = ["v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id", "friction", "delivered_to", "expires_at"];

/// A safe integer that is not -0 (the reference's `isInt`).
fn is_int(v: &Value) -> bool {
    is_safe_int(v) && !v.as_f64().is_some_and(|f| f == 0.0 && f.is_sign_negative())
}

fn u16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// The reference `cellCoordsError`: dimension path -> `[lo, hi]` index range or a distinct value set.
fn cell_coords_error(c: &Value) -> Option<String> {
    let Some(m) = c.as_object().filter(|m| !m.is_empty() && m.len() <= 64) else { return Some("coords must be an object of 1..64 dimensions".into()) };
    for k in crate::missing_context::js_keys(m) {
        let v = &m[k.as_str()];
        if !(1..=256).contains(&u16_len(&k)) {
            return Some("a coordinate path must be 1..256 characters".into());
        }
        let a = v.as_array();
        if let Some([lo, hi]) = a.filter(|r| r.iter().all(is_int)).map(Vec::as_slice) {
            // is_int holds for both, so both are numbers
            let (lo, hi) = (lo.as_f64(), hi.as_f64());
            if !(lo >= Some(0.0) && lo <= hi) {
                return Some(format!("coords '{k}': need 0 <= lo <= hi"));
            }
        } else if let Some(set) = a.filter(|s| (1..=256).contains(&s.len()) && s.iter().all(Value::is_string)) {
            let distinct: std::collections::HashSet<&str> = set.iter().filter_map(Value::as_str).collect();
            if distinct.len() != set.len() {
                return Some(format!("coords '{k}': values must be distinct"));
            }
        } else {
            return Some(format!("coords '{k}': an index range [lo, hi] or a value set"));
        }
    }
    None
}

/// The reference `intentRequiredShapeError(body, {signed: false})`: the unsigned body, members in the reference's check order.
fn intent_required_body_error(b: &Value) -> Option<String> {
    let Some(o) = b.as_object() else { return Some("not an object".into()) };
    for k in crate::missing_context::js_keys(o) {
        if k == "sig" {
            continue; // checked last, as the reference does
        }
        if !INTENT_REQUIRED_KEYS.contains(&k.as_str()) {
            return Some(format!("unknown member '{k}'"));
        }
    }
    if o.get("v").filter(|v| v.is_number()).and_then(Value::as_f64) != Some(1.0) || o.get("kind").and_then(Value::as_str) != Some("pca-intent-required") {
        return Some("not a pca-intent-required v1".into());
    }
    for k in ["session", "map_digest", "schema", "pcactn_digest", "action_digest"] {
        if !o.get(k).and_then(Value::as_str).is_some_and(crate::workflow::is_b32_str) {
            return Some(format!("{k} must be canonical base64url (32 bytes)"));
        }
    }
    let cell = o.get("cell").and_then(Value::as_object);
    let cell_ok = cell.is_some_and(|c| c.len() == 2 && c.contains_key("coords") && c.get("verb").and_then(Value::as_str).is_some_and(|v| !v.is_empty()));
    if !cell_ok {
        return Some("cell must be {verb, coords}".into());
    }
    if let Some(e) = cell_coords_error(&cell.unwrap()["coords"]) {
        return Some(e);
    }
    if o.get("reason").and_then(Value::as_str) != Some("uncertain") {
        return Some("reason must be 'uncertain'".into());
    }
    let qid_ok = o.get("question_id").and_then(Value::as_str).is_some_and(|q| (1..=64).contains(&q.len()) && q.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'));
    if !qid_ok {
        return Some("question_id must match [A-Za-z0-9_-]{1,64}".into());
    }
    if !o.get("friction").and_then(Value::as_str).is_some_and(|f| ["tap", "hold", "typed", "device"].contains(&f)) {
        return Some("unknown friction tier".into());
    }
    if !o.get("delivered_to").and_then(Value::as_str).is_some_and(|d| d == "wallet" || d == "agent") {
        return Some("delivered_to must be 'wallet' or 'agent'".into());
    }
    if !o.get("expires_at").is_some_and(|e| is_int(e) && e.as_f64().is_some_and(|f| f >= 0.0)) {
        return Some("expires_at must be a non-negative safe integer".into());
    }
    if o.contains_key("sig") {
        return Some("an unsigned body must not carry sig".into());
    }
    None
}

/// Sign an intent-required question as the site: `sig = {alg, kid, value, pq_value?}` over
/// `"atlas-pca/intent-required/v1\0" || strictCanonical(body)`, pinned by the same discovery key entry as the action schema.
pub fn sign_intent_required(body: &Value, kid: &str, site: &KeyPair, s: &Suite) -> Result<Value, String> {
    if let Some(e) = intent_required_body_error(body) {
        return Err(format!("signIntentRequired: {e}"));
    }
    let (sig, pq_sig) = sign_with_suite(s, Some(site), &strict_msg(INTENT_REQUIRED_DOMAIN, body)?)?;
    let mut out = body.clone();
    out["sig"] = site_sig(s.alg.unwrap_or("ed25519"), kid, sig, pq_sig);
    Ok(out)
}

// ---- progress steps ----------------------------------------------------------------------------------------------------------

/// The holder's signed progress step `{step, holder, sig}`: Ed25519 over `canonical({d: "atlas-pca/progress-step/v2", b})`, `b`
/// binding the holder, goal, action, before/after state digests, sequence, chain link and step digest. Like the reference it
/// signs the step as given (the verifier re-runs the deterministic step check); a member the step lacks is left out of `b`.
pub fn sign_progress_step(step: &Value, holder: &KeyPair) -> Result<Value, String> {
    let mut b = Map::new();
    b.insert("holder".into(), json!(holder.public));
    for (k, from) in [("goal_commitment", "goal_commitment"), ("action_digest", "action_digest"), ("before_digest", "before_digest"), ("after_digest", "after_digest"), ("seq", "seq"), ("prev", "prev"), ("step_digest", "digest")] {
        if let Some(v) = step.get(from) {
            b.insert(k.into(), v.clone());
        }
    }
    let sig = b64(&holder.sign(&native_msg("atlas-pca/progress-step/v2", &Value::Object(b))?));
    Ok(json!({"step": step, "holder": holder.public, "sig": sig}))
}

fn sign_wire(domain: &str, kind: &str, body: &Value, key: &KeyPair, s: &Suite, what: &str, valid: fn(&Value) -> bool) -> Result<Value, String> {
    let mut b = obj(body, what)?.clone();
    b.insert("v".into(), json!(1));
    b.insert("kind".into(), json!(kind));
    let out = sign_artifact(domain, &Value::Object(b), key, s)?;
    if !valid(&out) {
        return Err(format!("{what}: malformed {kind} (the verifier would refuse it)"));
    }
    Ok(out)
}

/// The site's signed label receipt `{v: 1, kind: "pca-labels", ...body}` (suite fields bound into the body).
pub fn sign_labels(body: &Value, site: &KeyPair, s: &Suite) -> Result<Value, String> {
    sign_wire("atlas-pca/labels/v1\0", "pca-labels", body, site, s, "signLabels", crate::intent_wb::validate_labels_wire)
}

/// The oracle's signed fact `{v: 1, kind: "pca-fact", name, subject, value, t_obs, oracle}` (suite fields bound into the body).
pub fn sign_fact(body: &Value, oracle: &KeyPair, s: &Suite) -> Result<Value, String> {
    sign_wire("atlas-pca/fact/v1\0", "pca-fact", body, oracle, s, "signFact", crate::intent_wb::validate_fact_wire)
}

/// The site's signed offer set (`pca-offer-set` v1; the body carries its own `v` / `kind`), suite fields bound into the body.
/// As in the reference, only the strict canonical profile is checked before signing (the verifier checks the wire).
pub fn sign_offer_set(body: &Value, site: &KeyPair, s: &Suite) -> Result<Value, String> {
    sign_artifact("atlas-pca/offer-set/v1\0", body, site, s)
}

// ---- policy templates and overlays ------------------------------------------------------------------------------------------

/// The organisation's signed policy template `{def, signer, sig}` (a well-formed definition only).
pub fn sign_template(def: &Value, signer: &KeyPair) -> Result<Value, String> {
    if let Some(e) = crate::template_def_error(def) {
        return Err(format!("signTemplate: {e}"));
    }
    let d = crate::template_digest(def).ok_or("signTemplate: the definition is outside the strict JSON profile")?;
    Ok(json!({"def": def, "signer": signer.public, "sig": b64(&signer.sign(&id_msg("atlas-pca/policy-template/v1\0", &d)))}))
}

/// The organisation's signed tighten overlay `{overlay, signer, sig}` (an overlay only adds where conditions and caveats).
pub fn sign_tighten(overlay: &Value, signer: &KeyPair) -> Result<Value, String> {
    if let Some(e) = crate::tighten_overlay_error(overlay) {
        return Err(format!("signTighten: {e}"));
    }
    let d = hash_canonical_strict(overlay).ok_or("signTighten: the overlay is outside the strict JSON profile")?;
    Ok(json!({"overlay": overlay, "signer": signer.public, "sig": b64(&signer.sign(&id_msg("atlas-pca/template-tighten/v1\0", &d)))}))
}

// ---- revocation epoch, constitution, safety evidence --------------------------------------------------------------------------

const EPOCH_FIELDS: [&str; 7] = ["instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"];

/// The guardian's signed revocation epoch: the seven epoch members, `guardian`, and the suite fields, signed under
/// `"atlas-pca/revepoch/v1\0"` with `alg`/`pq_pk` bound into the body.
pub fn sign_revocation_epoch(guardian: &KeyPair, body: &Value, s: &Suite) -> Result<Value, String> {
    let mut b = Map::new();
    for k in EPOCH_FIELDS {
        b.insert(k.into(), body.get(k).cloned().ok_or_else(|| format!("signRevocationEpoch: {k} required"))?);
    }
    for k in ["epoch", "set_size", "issued_at", "not_after"] {
        if !is_safe_int(&b[k]) || b[k].as_f64().is_some_and(|f| f < 0.0) {
            return Err(format!("signRevocationEpoch: {k} must be a non-negative safe integer"));
        }
    }
    let mut out = sign_artifact("atlas-pca/revepoch/v1\0", &Value::Object(b), guardian, s)?;
    out["guardian"] = json!(guardian.public);
    Ok(out)
}

/// The principal's signed constitution: the body plus its content address `id` and the signature over
/// `"atlas-pca/constitution/v1\0" || sha256(id)`. A malformed constitution is refused with every problem listed.
pub fn sign_constitution(principal: &KeyPair, c: &Value) -> Result<Value, String> {
    let problems = crate::prohibitions::validate_constitution(c);
    if !problems.is_empty() {
        return Err(format!("signConstitution: {}", problems.join("; ")));
    }
    let mut body = obj(c, "signConstitution")?.clone();
    body.remove("id");
    body.remove("sig");
    let id = crate::prohibitions::constitution_id(c).ok_or("signConstitution: the constitution is outside the strict JSON profile")?;
    body.insert("id".into(), json!(id));
    body.insert("sig".into(), json!(b64(&principal.sign(&id_msg(crate::prohibitions::CONSTITUTION_SIG_DOMAIN, &id)))));
    Ok(Value::Object(body))
}

/// Signed safety evidence `{evidence, signer, id, sig}`: `id` binds the signer, the evidence digest and the constitution, action
/// and state digests. Evidence whose digests could not be computed is refused (nothing to bind).
pub fn sign_safety_evidence(signer: &KeyPair, evidence: &Value) -> Result<Value, String> {
    if evidence.get("v").and_then(Value::as_f64) != Some(crate::prohibitions::EVIDENCE_VERSION as f64) || !evidence.get("v").is_some_and(Value::is_number) {
        return Err("signSafetyEvidence: unsupported evidence".into());
    }
    for k in ["constitution", "action_digest", "state_digest"] {
        if !evidence.get(k).and_then(Value::as_str).is_some_and(|d| !d.is_empty() && d != "<unhashable>") {
            return Err("signSafetyEvidence: unbound evidence".into());
        }
    }
    let id = crate::prohibitions::safety_binding_id(evidence, &signer.public).ok_or("signSafetyEvidence: unbound evidence")?;
    let sig = b64(&signer.sign(&id_msg(crate::prohibitions::SAFETY_EVIDENCE_SIG_DOMAIN, &id)));
    Ok(json!({"evidence": evidence, "signer": signer.public, "id": id, "sig": sig}))
}
