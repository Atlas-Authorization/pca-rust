//! FROST post-quantum composition (port of `frost-pq.ts`): the group-algorithm registry (`ed25519` | `hybrid-ed25519-ml-dsa-65`), the signer-set
//! digest, the HYBRID co-sign (the FROST Ed25519 aggregate PLUS a guardian ML-DSA-65 signature over a representative that binds the group
//! key, sha256(message) and the signer set) and its verifier. The PQ quorum block (t ML-DSA-65 signatures by distinct pooled keys over
//! `domain || sha256(message)`) is [`crate::pq_threshold`]'s: its representative, pool normalisation, signer and verifier are re-exported here.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::agent::{sign_with_suite, PqKeyPair, Suite};
use crate::frost::{frost_cosign, FrostParticipantShare};
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict};

pub use crate::pq_threshold::{
    normalize_pq_quorum_pool, pq_quorum_representative, sign_pq_quorum, verify_pq_quorum, MAX_PQ_QUORUM_ENTRIES, PQ_QUORUM_ALG, PQ_QUORUM_VERSION,
};

/// The default group algorithm.
pub const DEFAULT_FROST_GROUP_ALG: &str = "ed25519";
const KNOWN: [&str; 2] = ["ed25519", "hybrid-ed25519-ml-dsa-65"];
const COSIGN_DOMAIN: &[u8] = b"atlas-pca/frost-pq-cosign/v1\0";
const SIGNER_SET_DOMAIN: &[u8] = b"atlas-pca/frost-signer-set/v1\0";
const ML_DSA_65_PK_BYTES: usize = 1952;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn known(v: &Value) -> bool {
    v.as_str().is_some_and(|s| KNOWN.contains(&s))
}

/// The group algorithm a signature names: `None` given (absent) is the default, a known name itself, anything else `None` (refused).
pub fn resolve_frost_group_alg(group_alg: Option<&Value>) -> Option<String> {
    match group_alg {
        None => Some(DEFAULT_FROST_GROUP_ALG.to_string()),
        Some(v) if known(v) => v.as_str().map(String::from),
        Some(_) => None,
    }
}

/// `sha256(domain || canonical JSON of the sorted distinct participant ids)`. `Err` for an empty set or an id that is not a positive safe
/// integer.
pub fn frost_signer_set_digest(signer_set: &Value) -> Result<Vec<u8>, String> {
    let list = signer_set.as_array().filter(|l| !l.is_empty()).ok_or("frostSignerSetDigest: empty signer set")?;
    let mut ids: Vec<f64> = Vec::new();
    for v in list {
        let f = v.as_f64().filter(|f| v.is_number() && f.fract() == 0.0 && *f > 0.0 && *f <= MAX_SAFE);
        let f = f.ok_or("frostSignerSetDigest: participant identifiers must be positive safe integers")?;
        if !ids.contains(&f) {
            ids.push(f);
        }
    }
    ids.sort_by(|a, b| a.total_cmp(b));
    let canon = canonicalize_strict(&Value::Array(ids.iter().map(|f| json!(*f as i64)).collect()))?;
    let mut m = SIGNER_SET_DOMAIN.to_vec();
    m.extend_from_slice(canon.as_bytes());
    Ok(Sha256::digest(&m).to_vec())
}

/// The bytes the guardian ML-DSA co-signature covers: `domain || groupAlg || 0x00 || groupPublicKey || sha256(message) || signer-set digest`.
pub fn frost_cosign_representative(group_public_key_b64u: &Value, message: &[u8], signer_set: &Value, group_alg: &Value) -> Result<Vec<u8>, String> {
    let gpk = group_public_key_b64u
        .as_str()
        .and_then(|g| decode_b64u_strict(g, Some(32)))
        .ok_or("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point")?;
    let mut out = COSIGN_DOMAIN.to_vec();
    out.extend_from_slice(crate::intent_v2::js_value_string(group_alg).as_bytes());
    out.push(0);
    out.extend_from_slice(&gpk);
    out.extend_from_slice(&Sha256::digest(message));
    out.extend_from_slice(&frost_signer_set_digest(signer_set)?);
    Ok(out)
}

/// Run the quorum in process: `{sig}` (classical) or `{sig, groupAlg, pq_sig, pq_pk}`. `group_alg` default `ed25519`; the hybrid algorithm needs
/// the guardian ML-DSA-65 key pair.
pub fn sign_hybrid_frost_cosign(
    group_public_key: &[u8],
    quorum: &[FrostParticipantShare],
    message: &[u8],
    group_alg: Option<&Value>,
    guardian: Option<&PqKeyPair>,
    threshold: Option<i64>,
) -> Result<Value, String> {
    let alg = group_alg.filter(|a| !a.is_null()).cloned().unwrap_or_else(|| json!(DEFAULT_FROST_GROUP_ALG));
    if !known(&alg) {
        return Err(format!("signHybridFrostCosign: unknown groupAlg '{}'", crate::intent_v2::js_value_string(&alg)));
    }
    let sig = b64_encode(&frost_cosign(group_public_key, quorum, message, threshold)?);
    if alg == json!("ed25519") {
        return Ok(json!({"sig": sig}));
    }
    let pq = guardian.ok_or_else(|| format!("signHybridFrostCosign: '{}' requires a guardian ML-DSA-65 key pair", crate::intent_v2::js_value_string(&alg)))?;
    let ids: Vec<Value> = quorum.iter().map(|p| json!(p.identifier)).collect();
    let rep = frost_cosign_representative(&json!(b64_encode(group_public_key)), message, &Value::Array(ids), &alg)?;
    let (pq_sig, _) = sign_with_suite(&Suite { alg: Some("ml-dsa-65"), pq: Some(pq) }, None, &rep)?;
    Ok(json!({"sig": sig, "groupAlg": alg, "pq_sig": pq_sig, "pq_pk": pq.public}))
}

/// Verify a (hybrid) FROST co-signature: `{ok, groupAlg?, edOk, pqOk, reason?}`. The hybrid algorithm needs `guardian_pq_public_key` (the
/// REGISTERED guardian ML-DSA-65 key; the artifact's own `pq_pk` only has to match it) and BOTH halves must verify. `expect_group_alg` pins the
/// algorithm. Never fails.
pub fn verify_hybrid_frost_cosign(
    artifact: &Value,
    message: &[u8],
    group_public_key_b64u: &Value,
    signer_set: &Value,
    guardian_pq_public_key: Option<&Value>,
    expect_group_alg: Option<&Value>,
) -> Value {
    let deny = |reason: String, alg: Option<&str>| {
        let mut o = json!({"ok": false, "edOk": false, "pqOk": false});
        if let Some(a) = alg {
            o["groupAlg"] = json!(a);
        }
        o["reason"] = json!(reason);
        o
    };
    let Some(sig) = artifact.get("sig").and_then(Value::as_str).filter(|_| artifact.is_object()) else { return deny("malformed artifact".into(), None) };
    let Some(gpk) = group_public_key_b64u.as_str().filter(|g| decode_b64u_strict(g, Some(32)).is_some()) else {
        return deny("malformed group public key".into(), None);
    };
    let Some(alg) = resolve_frost_group_alg(artifact.get("groupAlg")) else {
        return deny(format!("unknown groupAlg '{}'", crate::intent_strict::js_opt_string(artifact.get("groupAlg"))), None);
    };
    // `!== undefined`: an explicit null is an (unknown) expectation, not an absent one
    if let Some(want) = expect_group_alg {
        if !known(want) {
            return deny(format!("unknown expected groupAlg '{}'", crate::intent_v2::js_value_string(want)), None);
        }
        if want.as_str() != Some(alg.as_str()) {
            return deny(format!("groupAlg '{alg}' does not match the required '{}'", want.as_str().unwrap_or("")), Some(alg.as_str()));
        }
    }
    let ed_ok = crate::verify_b64u(gpk, message, sig);
    if alg == "ed25519" {
        return if ed_ok { json!({"ok": true, "groupAlg": alg, "edOk": true, "pqOk": false}) } else { deny("FROST Ed25519 group signature did not verify".into(), Some(alg.as_str())) };
    }
    let registered = guardian_pq_public_key.and_then(Value::as_str).filter(|r| decode_b64u_strict(r, Some(ML_DSA_65_PK_BYTES)).is_some());
    let Some(registered) = registered else { return deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key".into(), Some(alg.as_str())) };
    if artifact.get("pq_pk").is_some_and(|p| !p.is_null()) && artifact["pq_pk"].as_str() != Some(registered) {
        return deny("artifact pq_pk does not match the registered guardian ML-DSA key".into(), Some(alg.as_str()));
    }
    let Some(pq_sig) = artifact.get("pq_sig").and_then(Value::as_str) else {
        return deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing".into(), Some(alg.as_str()));
    };
    let pq_ok = frost_cosign_representative(group_public_key_b64u, message, signer_set, &json!(alg)).is_ok_and(|rep| {
        let key = crate::pinned::PinnedPq::caller_vouched(registered);
        crate::verify_suite(Some(&json!("ml-dsa-65")), "", key.as_ref(), &rep, Some(&json!(pq_sig)), None)
    });
    if !ed_ok || !pq_ok {
        let reason = if !ed_ok { "FROST Ed25519 group signature did not verify" } else { "guardian ML-DSA-65 co-signature did not verify" };
        return json!({"ok": false, "groupAlg": alg, "edOk": ed_ok, "pqOk": pq_ok, "reason": reason});
    }
    json!({"ok": true, "groupAlg": alg, "edOk": true, "pqOk": true})
}
