//! Post-quantum threshold step-up verification (`@atlasauth/pca-pq-threshold`): the signed FROST group descriptor that pins the
//! threshold `t` to the group key, the ML-DSA-65 pqT-of-m co-signer quorum (a multi-signature of single-party keys, not a
//! threshold scheme), and the hybrid verdict that needs BOTH. The FROST aggregate is checked as the plain strict Ed25519
//! signature it is; the quorum runs on the vetted `fips204` ML-DSA-65 verifier already used by the core.
//!
//! Inputs are JSON values with JavaScript field-read semantics: an absent member and a wrong-typed member are distinct from
//! null, a raw `Uint8Array` key is its base64url string, and every verifier is total (a malformed input is a refusal, never a
//! panic). A reference throw is an `Err`.
//!
//! Hybrid signing (`hybrid_threshold_sign`, `sign_pq_quorum`) lives at the end of this file; FROST itself is frost.rs.
//! A string `pqPublicKeys` is refused (JavaScript would iterate its characters).
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, pq_verify, sha, threshold_message, verify_b64u, Pq};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

pub const GROUP_DESCRIPTOR_VERSION: u32 = 1;
pub const GROUP_SUITE: &str = "frost-ed25519";
pub const MAX_GROUP_SIZE: usize = 1024;
pub const HYBRID_ARTIFACT_VERSION: u32 = 2;
pub const HYBRID_CLASSICAL_ALG: &str = "frost-ed25519";
pub const PQ_QUORUM_VERSION: u32 = 2;
pub const PQ_QUORUM_ALG: &str = "ml-dsa-65";
pub const MAX_PQ_QUORUM_ENTRIES: usize = 256;
/// `HYBRID_PQ_ALG` / `MAX_PQ_SIGNER_ENTRIES` of the reference: the co-signature algorithm and how many entries of a presented block are examined.
pub const HYBRID_PQ_ALG: &str = PQ_QUORUM_ALG;
pub const MAX_PQ_SIGNER_ENTRIES: usize = MAX_PQ_QUORUM_ENTRIES;

const DESCRIPTOR_DOMAIN: &[u8] = b"atlas-pca-pq-threshold/group-descriptor/v1\0";
const SIGNER_SET_DOMAIN: &[u8] = b"atlas-pca-pq-threshold/signer-set/v1\0";
const QUORUM_DOMAIN: &[u8] = b"atlas-pca/pq-quorum/v2\0";
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

// ---- JS helpers ------------------------------------------------------------------------------------------------------

/// `o[k]`: `None` is JS `undefined` (absent, or `o` is not an object); JSON null is `Some(Null)`.
fn get<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object().and_then(|m| m.get(k))
}

/// JS `typeof v === 'object' && v !== null` (arrays included).
fn is_obj(v: &Value) -> bool {
    v.is_object() || v.is_array()
}

fn num(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64)
}

fn is_integer(v: Option<&Value>) -> bool {
    num(v).is_some_and(|f| f.is_finite() && f.fract() == 0.0)
}

fn is_num(v: Option<&Value>, n: f64) -> bool {
    num(v) == Some(n)
}

fn is_str(v: Option<&Value>, s: &str) -> bool {
    v.and_then(Value::as_str) == Some(s)
}

/// ECMAScript `String(v)` (`undefined` for an absent member).
fn js(v: Option<&Value>) -> String {
    v.map_or_else(|| "undefined".to_string(), crate::intent_v2::js_value_string)
}

fn prefixed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = domain.to_vec();
    m.extend_from_slice(body);
    m
}

// ---- signed group descriptor -----------------------------------------------------------------------------------------

/// `b64u(sha256(domain || canonical([{id, pk}] sorted by id)))` over the FROST verification shares. Order-insensitive; ids are
/// distinct positive safe integers; every share is a canonical b64u(32) value.
pub fn signer_set_commitment(participants: &Value) -> Result<String, String> {
    let list = participants
        .as_array()
        .filter(|l| !l.is_empty() && l.len() <= MAX_GROUP_SIZE)
        .ok_or_else(|| format!("signerSetCommitment: need 1..{MAX_GROUP_SIZE} participants"))?;
    let mut rows: Vec<(i64, String)> = Vec::with_capacity(list.len());
    for p in list {
        let id = get(p, "identifier");
        let f = num(id).filter(|f| f.is_finite() && f.fract() == 0.0 && *f > 0.0 && *f <= MAX_SAFE);
        let f = f.ok_or("signerSetCommitment: participant identifiers must be positive safe integers")?;
        let pk = get(p, "publicKey").and_then(Value::as_str).filter(|s| decode_b64u_strict(s, Some(32)).is_some());
        let pk = pk.ok_or("signerSetCommitment: verification share is not a canonical b64u(32) value")?;
        rows.push((f as i64, pk.to_string()));
    }
    rows.sort_by_key(|r| r.0);
    if rows.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("signerSetCommitment: duplicate participant identifier".into());
    }
    let canon = Value::Array(rows.iter().map(|(id, pk)| json!({ "id": id, "pk": pk })).collect());
    let body = canonicalize_strict(&canon)?;
    Ok(b64_encode(&sha(&prefixed(SIGNER_SET_DOMAIN, body.as_bytes()))))
}

fn descriptor_bytes(d: &Value) -> Result<Vec<u8>, String> {
    let body = json!({ "v": d["v"], "suite": d["suite"], "group_pk": d["groupPublicKey"], "t": d["t"], "n": d["n"], "signer_set": d["signerSetCommitment"] });
    Ok(prefixed(DESCRIPTOR_DOMAIN, canonicalize_strict(&body)?.as_bytes()))
}

/// Issue a descriptor at DKG / dealing time: `{descriptor, authority, sig}`. `authority_seed` is the setup authority's 32-byte
/// Ed25519 seed; `group_public_key` is a canonical b64u(32) string; `t` a JSON number with `1 <= t <= n`.
pub fn issue_group_descriptor(authority_seed: &[u8], group_public_key: &Value, t: &Value, participants: &Value) -> Result<Value, String> {
    let n = participants.as_array().map(Vec::len).ok_or("issueGroupDescriptor: participants must be a list")?;
    let tf = num(Some(t)).filter(|f| f.is_finite() && f.fract() == 0.0 && *f >= 1.0 && *f <= n as f64);
    let tf = tf.ok_or_else(|| format!("issueGroupDescriptor: need 1 <= t <= n (t={}, n={n})", js(Some(t))))?;
    let gpk = group_public_key.as_str().filter(|s| decode_b64u_strict(s, Some(32)).is_some());
    let gpk = gpk.ok_or("issueGroupDescriptor: group public key is not canonical b64u(32)")?;
    let seed: [u8; 32] = authority_seed.try_into().map_err(|_| "issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key")?;
    let t_out = tf as i64;
    let descriptor = json!({
        "v": GROUP_DESCRIPTOR_VERSION, "suite": GROUP_SUITE, "groupPublicKey": gpk, "t": t_out, "n": n,
        "signerSetCommitment": signer_set_commitment(participants)?,
    });
    let sk = SigningKey::from_bytes(&seed);
    let sig = sk.sign(&descriptor_bytes(&descriptor)?);
    Ok(json!({ "descriptor": descriptor, "authority": b64_encode(&sk.verifying_key().to_bytes()), "sig": b64_encode(&sig.to_bytes()) }))
}

fn fail(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

/// `{ok: true, descriptor}` or `{ok: false, reason}`; never panics. `exp` carries `trustedAuthorities`, `groupKey`, `t` and
/// optionally `signerSetCommitment`. The descriptor must verify under a pinned authority, be for exactly the pinned group key and
/// have `t` EQUAL to the threshold the verifier requires.
pub fn verify_group_descriptor(s: &Value, exp: &Value) -> Value {
    verify_gd(s, exp).unwrap_or_else(|_| fail("group descriptor could not be verified (malformed)"))
}

fn verify_gd(s: &Value, exp: &Value) -> Result<Value, String> {
    if !is_obj(s) {
        return Ok(fail("no signed group descriptor: the threshold is unattested"));
    }
    let d = get(s, "descriptor").filter(|d| is_obj(d));
    let (auth, sig) = (get(s, "authority").and_then(Value::as_str), get(s, "sig").and_then(Value::as_str));
    let (Some(d), Some(auth), Some(sig)) = (d, auth, sig) else { return Ok(fail("malformed group descriptor")) };
    if !is_num(get(d, "v"), GROUP_DESCRIPTOR_VERSION as f64) || !is_str(get(d, "suite"), GROUP_SUITE) {
        return Ok(fail("unsupported group descriptor version or suite"));
    }
    let (Some(dg), Some(dssc)) = (get(d, "groupPublicKey").and_then(Value::as_str), get(d, "signerSetCommitment").and_then(Value::as_str)) else {
        return Ok(fail("malformed group descriptor"));
    };
    let (dt, dn) = (get(d, "t"), get(d, "n"));
    let (dtf, dnf) = (num(dt).unwrap_or(0.0), num(dn).unwrap_or(0.0));
    if !is_integer(dt) || !is_integer(dn) || dtf < 1.0 || dnf < dtf || dnf > MAX_GROUP_SIZE as f64 {
        return Ok(fail("malformed group descriptor: need 1 <= t <= n"));
    }
    // a non-array trustedAuthorities throws in the reference (`.map` of a non-array), which is the generic malformed refusal
    let authorities = get(exp, "trustedAuthorities").and_then(Value::as_array).ok_or("trustedAuthorities must be an array")?;
    if !authorities.iter().any(|a| a.as_str() == Some(auth)) {
        return Ok(fail("group descriptor authority is not trusted"));
    }
    if decode_b64u_strict(auth, Some(32)).is_none() || decode_b64u_strict(sig, Some(64)).is_none() {
        return Ok(fail("malformed authority key or signature"));
    }
    if !verify_b64u(auth, &descriptor_bytes(d)?, sig) {
        return Ok(fail("group descriptor signature does not verify"));
    }
    if get(exp, "groupKey").and_then(Value::as_str) != Some(dg) {
        return Ok(fail("group descriptor is for a different group key"));
    }
    let et = get(exp, "t");
    let etf = num(et).unwrap_or(0.0);
    if !is_integer(et) || etf < 1.0 {
        return Ok(fail("required t must be a positive integer"));
    }
    if dtf != etf {
        return Ok(fail(&format!("group was set up as {}-of-{} but {} is required: the threshold is not bound to this key", js(dt), js(dn), js(et))));
    }
    if let Some(pin) = get(exp, "signerSetCommitment") {
        if pin.as_str() != Some(dssc) {
            return Ok(fail("group descriptor is for a different signer set"));
        }
    }
    Ok(json!({ "ok": true, "descriptor": d }))
}

// ---- ML-DSA-65 co-signer quorum --------------------------------------------------------------------------------------

/// The bytes every co-signature covers: `domain || sha256(message)`.
pub fn pq_quorum_representative(message: &[u8]) -> Vec<u8> {
    prefixed(QUORUM_DOMAIN, &sha(message))
}

/// The trusted pool as canonical base64url strings (sorted); entries that are not a well-formed ML-DSA-65 public key are ignored.
/// Err when `pks` is not an array.
pub fn normalize_pq_quorum_pool(pks: &Value) -> Result<BTreeSet<String>, String> {
    let items = pks.as_array().ok_or("normalizePqQuorumPool: expected an array of public keys")?;
    Ok(items.iter().filter_map(Value::as_str).filter(|s| decode_b64u_strict(s, Some(crate::ML_DSA_65_PUBLIC_KEY_BYTES)).is_some()).map(String::from).collect())
}

fn verdict(ok: bool, count: usize, pq_t: Option<&Value>, reason: Option<String>) -> Value {
    let mut m = Map::new();
    m.insert("ok".into(), Value::Bool(ok));
    m.insert("count".into(), json!(count));
    if let Some(t) = pq_t {
        m.insert("need".into(), t.clone());
    }
    if let Some(r) = reason {
        m.insert("reason".into(), Value::String(r));
    }
    Value::Object(m)
}

/// Counts DISTINCT trusted keys whose ML-DSA-65 co-signature verifies over `message`; `ok` iff the count reaches `pqT`. Total; a
/// missing, v1 or unknown block version is refused before any verification. `need` echoes `pqT` as given (absent stays absent).
pub fn verify_pq_quorum(block: &Value, message: &[u8], trusted_pool: &BTreeSet<String>, pq_t: Option<&Value>) -> Value {
    let no = |reason: &str| verdict(false, 0, pq_t, Some(reason.to_string()));
    let tf = num(pq_t).filter(|f| f.is_finite() && f.fract() == 0.0 && *f >= 1.0);
    let Some(tf) = tf else { return no("pqT must be a positive integer") };
    if !is_obj(block) {
        return no("malformed pq block");
    }
    let v = get(block, "v");
    if v.is_none() {
        return no("pq quorum version missing (pre-0.5 format is refused)");
    }
    if is_num(v, 1.0) {
        return no("pq quorum version 1 is no longer accepted (pre-0.5 format)");
    }
    if !is_num(v, PQ_QUORUM_VERSION as f64) {
        return no("unsupported pq quorum version");
    }
    let (Some(list), true) = (get(block, "signers").and_then(Value::as_array), is_str(get(block, "alg"), PQ_QUORUM_ALG)) else {
        return no("malformed pq block");
    };
    let rep = pq_quorum_representative(message);
    let mut counted: BTreeSet<&str> = BTreeSet::new();
    for e in list.iter().take(MAX_PQ_QUORUM_ENTRIES) {
        let (Some(pk), Some(sg)) = (get(e, "pk").and_then(Value::as_str), get(e, "sig").and_then(Value::as_str)) else { continue };
        if !trusted_pool.contains(pk) || counted.contains(pk) {
            continue;
        }
        let (Some(pkb), Some(sgb)) = (decode_b64u_strict(pk, Some(crate::ML_DSA_65_PUBLIC_KEY_BYTES)), decode_b64u_strict(sg, None)) else { continue };
        if pq_verify(Pq::MlDsa65, &pkb, &rep, &sgb) {
            counted.insert(pk);
        }
    }
    if counted.len() as f64 >= tf {
        return verdict(true, counted.len(), pq_t, None);
    }
    let reason = format!("post-quantum quorum short: {} of {} required ML-DSA co-signatures", counted.len(), js(pq_t));
    verdict(false, counted.len(), pq_t, Some(reason))
}

// ---- hybrid verification ---------------------------------------------------------------------------------------------

/// `None` (a reason is `Some`) when the signed descriptor pins `opts.t` to `opts.groupKey` under a trusted authority.
fn check_descriptor(opts: &Value) -> Option<String> {
    let mut exp = Map::new();
    for k in ["trustedAuthorities", "groupKey", "t", "signerSetCommitment"] {
        if let Some(v) = get(opts, k) {
            exp.insert(k.into(), v.clone());
        }
    }
    let r = verify_group_descriptor(get(opts, "groupDescriptor").unwrap_or(&Value::Null), &Value::Object(exp));
    if r["ok"].as_bool() == Some(true) {
        None
    } else {
        Some(r["reason"].as_str().unwrap_or("group descriptor could not be verified (malformed)").to_string())
    }
}

/// The hybrid verdict `{ok, frost, pq, reason?}`: fails closed unless the FROST aggregate verifies under the TRUSTED group key
/// (whose threshold the signed descriptor pins, and which the artifact's declared `t` may not undercut) AND at least `pqT`
/// distinct trusted ML-DSA-65 keys co-signed the same action message. `opts`: groupKey, pqPublicKeys, t, pqT, groupDescriptor,
/// trustedAuthorities, signerSetCommitment?.
pub fn verify_hybrid_threshold(action: &Value, artifact: &Value, opts: &Value) -> Value {
    verify_hybrid_inner(action, artifact, opts).unwrap_or_else(|_| {
        let reason = "malformed action or verifier options";
        json!({ "ok": false, "frost": false, "pq": { "ok": false, "count": 0, "need": 0, "reason": reason }, "reason": reason })
    })
}

fn verify_hybrid_inner(action: &Value, artifact: &Value, opts: &Value) -> Result<Value, String> {
    let version = get(artifact, "v");
    let pq_t = get(opts, "pqT");
    if !is_num(version, HYBRID_ARTIFACT_VERSION as f64) {
        let reason = match version {
            None => "artifact version missing (pre-0.5 format is refused)",
            Some(_) if is_num(version, 1.0) => "artifact version 1 is no longer accepted (pre-0.5 format)",
            Some(_) => "unsupported artifact version",
        };
        return Ok(json!({ "ok": false, "frost": false, "pq": verdict(false, 0, pq_t, Some(reason.to_string())), "reason": reason }));
    }
    let message = threshold_message(action.as_object().ok_or("action must be an object")?)?;
    let trusted = get(opts, "groupKey").and_then(Value::as_str).filter(|s| decode_b64u_strict(s, Some(32)).is_some());
    let pool = normalize_pq_quorum_pool(get(opts, "pqPublicKeys").ok_or("pqPublicKeys is required")?)?;

    let descriptor_reason = check_descriptor(opts);
    let t = get(opts, "t");
    let tf = num(t).unwrap_or(0.0);
    let frost = get(artifact, "frost").filter(|f| f.is_object() && is_str(get(f, "alg"), HYBRID_CLASSICAL_ALG));
    let (frost_ok, frost_reason) = match (trusted, frost) {
        _ if !is_integer(t) || tf < 1.0 => (false, Some("t must be a positive integer".to_string())),
        (None, _) => (false, Some("trusted FROST group key is not a canonical b64u(32) point".to_string())),
        (_, None) => (false, Some("malformed or missing FROST part".to_string())),
        _ if descriptor_reason.is_some() => (false, descriptor_reason),
        (Some(_), Some(f)) if !is_integer(get(f, "t")) || num(get(f, "t")).unwrap_or(0.0) < tf => {
            (false, Some(format!("FROST declared threshold {} is below the required t={} (downgrade)", js(get(f, "t")), js(t))))
        }
        (Some(g), Some(f)) => match get(f, "sig").and_then(Value::as_str) {
            Some(sig) if verify_b64u(g, &message, sig) => (true, None),
            _ => (false, Some("FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)".to_string())),
        },
    };

    let pq = verify_pq_quorum(get(artifact, "pq").unwrap_or(&Value::Null), &message, &pool, pq_t);
    let ok = frost_ok && pq["ok"].as_bool() == Some(true);
    let mut out = Map::new();
    out.insert("ok".into(), Value::Bool(ok));
    out.insert("frost".into(), Value::Bool(frost_ok));
    if !ok {
        let reason = if frost_ok { pq["reason"].as_str().map(String::from) } else { frost_reason };
        if let Some(r) = reason {
            out.insert("reason".into(), Value::String(r));
        }
    }
    out.insert("pq".into(), pq);
    Ok(Value::Object(out))
}

// ---- folding into a PCActn step-up, the core threshold hook, and the full step-up verification --------------------------------------

/// `foldHybridStepUp`: `{pcactn, pq}`. The FROST aggregate becomes a `guardian` share of the PCActn's threshold container (the signed
/// body is unchanged: `threshold_message` excludes `threshold`); the post-quantum block travels beside it.
pub fn fold_hybrid_step_up(action: &Value, artifact: &Value) -> Result<Value, String> {
    let frost = get(artifact, "frost").filter(|f| f.is_object());
    let (true, Some(frost)) = (action.is_object(), frost) else { return Err("foldHybridStepUp: malformed action or artifact".into()) };
    let mut share = Map::new();
    share.insert("role".into(), json!("guardian"));
    if let Some(v) = get(frost, "group_pk") {
        share.insert("publicKey".into(), v.clone());
    }
    if let Some(v) = get(frost, "sig") {
        share.insert("sig".into(), v.clone());
    }
    let mut shares: Vec<Value> = get(action, "threshold").and_then(|t| get(t, "shares")).and_then(Value::as_array).cloned().unwrap_or_default();
    shares.push(Value::Object(share));
    let mut pcactn = action.clone();
    pcactn["threshold"] = crate::consts::assemble_threshold(&shares);
    let mut out = Map::new();
    out.insert("pcactn".into(), pcactn);
    if let Some(pq) = get(artifact, "pq") {
        out.insert("pq".into(), pq.clone());
    }
    Ok(Value::Object(out))
}

/// `createHybridThresholdVerifier`: the threshold hook enforcing the hybrid step-up. It returns a function of the PCActn giving
/// `{enforced: true, ok, reason?}`: ok only if the FROST aggregate folded into `pcactn.threshold` verifies (as an Ed25519 signature)
/// under the TRUSTED group key AND the pqT-of-m quorum holds over this action. `opts`: groupKey, pqPublicKeys, t, pqT, pqBlock,
/// groupDescriptor, trustedAuthorities, signerSetCommitment?. The configuration is snapshotted here: later edits by the caller do not
/// change what the verifier enforces. `Err` at creation for malformed `pqPublicKeys`, and from the hook only when the PCActn cannot be
/// canonicalised.
pub fn create_hybrid_threshold_verifier(opts: &Value) -> Result<impl Fn(&Value) -> Result<Value, String>, String> {
    let opts = opts.clone();
    let trusted = get(&opts, "groupKey").and_then(Value::as_str).filter(|s| decode_b64u_strict(s, Some(32)).is_some()).map(String::from);
    let pool = normalize_pq_quorum_pool(get(&opts, "pqPublicKeys").ok_or("pqPublicKeys is required")?)?;
    Ok(move |pcactn: &Value| -> Result<Value, String> {
        let no = |reason: &str| -> Result<Value, String> { Ok(json!({"enforced": true, "ok": false, "reason": reason})) };
        if let Some(d) = check_descriptor(&opts) {
            return no(&d);
        }
        let message = threshold_message(pcactn.as_object().ok_or("the PCActn must be an object")?)?;
        let Some(trusted) = &trusted else { return no("trusted FROST group key is not a canonical b64u(32) point") };
        let share = get(pcactn, "threshold").and_then(|t| get(t, "shares")).and_then(Value::as_array).and_then(|a| {
            a.iter().find(|m| get(m, "sig").is_some_and(Value::is_string) && get(m, "publicKey").and_then(Value::as_str) == Some(trusted.as_str()))
        });
        let Some(share) = share else { return no("no FROST aggregate for the trusted group key in the step-up") };
        if !get(share, "sig").and_then(Value::as_str).is_some_and(|sig| verify_b64u(trusted, &message, sig)) {
            return no("FROST aggregate does not verify under the trusted group key (quorum short or forged)");
        }
        let pq = verify_pq_quorum(get(&opts, "pqBlock").unwrap_or(&Value::Null), &message, &pool, get(&opts, "pqT"));
        if pq["ok"].as_bool() != Some(true) {
            return no(pq["reason"].as_str().filter(|r| !r.is_empty()).unwrap_or("post-quantum quorum short"));
        }
        Ok(json!({"enforced": true, "ok": true}))
    })
}

/// `verifyHybridStepUp`: the full verification of a folded step-up `{pcactn, pq}`: the core verification of the PCActn (plan-root check
/// off: a step-up is not an authorize call) plus the hybrid threshold hook, reported as the check `threshold`, and the standalone pq
/// verdict. `opts`: grant, groupKey, pqPublicKeys, t, pqT, groupDescriptor, trustedAuthorities, signerSetCommitment?, audience (string:
/// the native core always enforces the audience) and nowEpoch (epoch ms). Returns `{allow, core, pq, reason?}`.
pub fn verify_hybrid_step_up(step_up: &Value, opts: &Value) -> Result<Value, String> {
    let pcactn = get(step_up, "pcactn").filter(|p| p.is_object()).ok_or("verifyHybridStepUp: step-up has no pcactn")?;
    let pool = normalize_pq_quorum_pool(get(opts, "pqPublicKeys").ok_or("pqPublicKeys is required")?)?;
    let message = threshold_message(pcactn.as_object().ok_or("the PCActn must be an object")?)?;
    let pq = verify_pq_quorum(get(step_up, "pq").unwrap_or(&Value::Null), &message, &pool, get(opts, "pqT"));
    let mut hook_opts = Map::new();
    for k in ["groupKey", "pqPublicKeys", "t", "pqT", "groupDescriptor", "trustedAuthorities", "signerSetCommitment"] {
        if let Some(v) = get(opts, k) {
            hook_opts.insert(k.into(), v.clone());
        }
    }
    hook_opts.insert("pqBlock".into(), get(step_up, "pq").cloned().unwrap_or(Value::Null));
    let hook = create_hybrid_threshold_verifier(&Value::Object(hook_opts))?;
    let grant = get(opts, "grant").cloned().unwrap_or(Value::Null);
    let now = num(get(opts, "nowEpoch")).filter(|f| f.is_finite()).unwrap_or(0.0) as i64;
    let audience = get(opts, "audience").and_then(Value::as_str).unwrap_or("");
    let core =
        crate::verify_pcactn_core_with(pcactn, &grant, now, audience, &crate::VerifyOptions { insecure_skip_plan_root_check: true, ..Default::default() });
    let hv = hook(pcactn)?;
    let hook_ok = hv["ok"].as_bool() == Some(true);
    let mut checks: Map<String, Value> = core.checks.iter().map(|(k, v)| (k.clone(), Value::Bool(*v))).collect();
    checks.insert("threshold".into(), Value::Bool(hook_ok));
    let mut out = Map::new();
    out.insert("allow".into(), Value::Bool(core.allow && hook_ok));
    out.insert("core".into(), json!({"allow": core.allow, "checks": checks, "reason": core.reason, "reasons": core.reasons}));
    out.insert("pq".into(), pq);
    if !core.allow {
        out.insert("reason".into(), json!(core.reason));
    } else if !hook_ok {
        out.insert("reason".into(), json!(format!("threshold: {}", hv["reason"].as_str().unwrap_or_default())));
    }
    Ok(Value::Object(out))
}

// ---- hybrid signing --------------------------------------------------------------------------------------------------

/// The FROST group public key of a signing request: 32 raw bytes or its canonical base64url form.
pub enum GroupKeyInput<'a> {
    Bytes(&'a [u8]),
    B64u(&'a str),
}

/// `signPqQuorum`: one ML-DSA-65 co-signature per `(public key, secret key)` pair over the quorum representative. `pq_t` None
/// means the number of signers.
pub fn sign_pq_quorum(message: &[u8], key_pairs: &[crate::pq::RawKeyPair], pq_t: Option<i64>) -> Result<Value, String> {
    let rep = pq_quorum_representative(message);
    let mut signers = Vec::new();
    for k in key_pairs {
        let sig = crate::pq::ml_dsa_65_sign(&k.secret_key, &rep)?;
        signers.push(json!({ "pk": b64_encode(&k.public_key), "sig": b64_encode(&sig) }));
    }
    let t = pq_t.unwrap_or(signers.len() as i64);
    Ok(json!({ "v": PQ_QUORUM_VERSION, "alg": PQ_QUORUM_ALG, "pqT": t, "signers": signers }))
}

/// `hybridThresholdSign`: the FROST t-of-n aggregate plus one ML-DSA-65 co-signature per PQ signer, both over
/// `threshold_message(action)`. Fails closed on a short quorum, an invalid share or no PQ signer.
pub fn hybrid_threshold_sign(
    action: &Map<String, Value>,
    group_public_key: GroupKeyInput,
    quorum: &[crate::frost::FrostParticipantShare],
    t: i64,
    pq_signers: &[crate::pq::RawKeyPair],
    pq_t: Option<i64>,
) -> Result<Value, String> {
    if t < 1 {
        return Err(format!("hybridThresholdSign: frost.t must be a positive integer (got {t})"));
    }
    if (quorum.len() as i64) < t {
        return Err(format!("hybridThresholdSign: FROST quorum of {} is below the threshold t={t}", quorum.len()));
    }
    if pq_signers.is_empty() {
        return Err("hybridThresholdSign: at least one ML-DSA co-signer is required".into());
    }
    let message = threshold_message(action)?;
    let gk = match group_public_key {
        GroupKeyInput::Bytes(b) if b.len() == 32 => b.to_vec(),
        GroupKeyInput::Bytes(_) => return Err("hybridThresholdSign: FROST group public key must be 32 bytes".into()),
        GroupKeyInput::B64u(s) => decode_b64u_strict(s, Some(32)).ok_or("hybridThresholdSign: FROST group public key is not canonical b64u(32)")?,
    };
    let agg = crate::frost::frost_cosign(&gk, quorum, &message, Some(t))?;
    let pq = sign_pq_quorum(&message, pq_signers, pq_t)?;
    Ok(json!({
        "v": HYBRID_ARTIFACT_VERSION,
        "digest": b64_encode(&sha(&message)),
        "frost": { "alg": HYBRID_CLASSICAL_ALG, "group_pk": b64_encode(&gk), "sig": b64_encode(&agg), "t": t, "quorum": quorum.len() },
        "pq": pq,
    }))
}
