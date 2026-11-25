//! Sign-side counterparts of artifacts this crate already verifies, and the verifiers that were absent beside them:
//! classifier verdicts, intent-map attestations, principal re-approvals, registry key entries, accumulator receipts and
//! sequencer key sets. Each signs `utf8(domain) || strictCanonical(body)` with the suite fields bound into the body, exactly
//! like the reference, and refuses a suite this crate cannot sign with `unsupported_suite: <alg>`.

use crate::agent::{sign_artifact, sign_with_suite, KeyPair, Suite};
use crate::{canonicalize_strict, hash_canonical_strict, serde_json::json};
use serde_json::{Map, Value};

pub const INTENT_MAP_SIG_DOMAIN: &str = "atlas-pca/intent-map-sig/v1\0";
const INTENT_MAP_DOMAIN: &str = "atlas-pca/intent-map/v1";
const REAPPROVAL_DOMAIN: &str = "atlas-pca/action-reapproval/v1\0";
const REAPPROVAL_KIND: &str = "pca-reapproval";
const INTENT_ANCHOR_LOG: &str = "pca-intent:v1";
const ANCHOR_KINDS: [&str; 9] = ["statement", "map", "observation", "schema", "session", "delta", "receipt", "profile", "evidence"];
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn is_int(v: Option<&Value>) -> Option<f64> {
    let f = v?.as_f64()?;
    (v?.is_number() && f.fract() == 0.0 && f.abs() <= MAX_SAFE && !(f == 0.0 && f.is_sign_negative())).then_some(f)
}

/// `signClassifierVerdict(body, key, suite)`: the verdict body (`classifier`, `class`, ... as the reference) with `v: 1`,
/// `kind: "pca-intent-classification"` and `judge` = the key's identity, signed under `"atlas-pca/intent-classifier/v1\0"`.
pub fn sign_classifier_verdict(body: &Value, key: &KeyPair, s: &Suite) -> Result<Value, String> {
    let b = body.as_object().ok_or("signClassifierVerdict: body is not an object")?;
    let mut m = Map::new();
    m.insert("v".into(), json!(1));
    m.insert("kind".into(), json!("pca-intent-classification"));
    for (k, v) in b {
        if !["v", "kind", "judge", "sig", "alg", "pq_pk", "pq_sig"].contains(&k.as_str()) {
            m.insert(k.clone(), v.clone());
        }
    }
    m.insert("judge".into(), json!(key.public));
    sign_artifact(crate::intent_wb::CLASSIFIER_DOMAIN, &Value::Object(m), key, s)
}

// ---- intent map attestation ------------------------------------------------------------------------------------------------

/// `intentMapShapeError(m)`: structural check of an Intent Map (it does not replay the map). `None` = well-formed.
pub fn intent_map_shape_error(m: &Value) -> Option<String> {
    let o = match m.as_object() {
        Some(o) if o.get("v").and_then(Value::as_i64) == Some(1) && o.get("kind").and_then(Value::as_str) == Some("pca-intent-map") => o,
        _ => return Some("not an intent map v1".into()),
    };
    match o.get("intent_ref") {
        Some(Value::Null) => {}
        Some(Value::String(r)) if crate::decode_b64u_strict(r, Some(32)).is_some() => {}
        _ => return Some("intent_ref must be null or canonical base64url (32 bytes)".into()),
    }
    let mt = match o.get("metrics").and_then(Value::as_object) {
        Some(mt) => mt,
        None => return Some("metrics must be an object".into()),
    };
    if !is_int(mt.get("fidelity_est_ppm")).is_some_and(|f| (0.0..=1e6).contains(&f)) {
        return Some("metrics.fidelity_est_ppm must be an integer in [0, 1e6]".into());
    }
    if !is_int(mt.get("residual_risk_ppm")).is_some_and(|f| f >= 0.0) {
        return Some("metrics.residual_risk_ppm must be a non-negative integer".into());
    }
    None
}

/// `intentMapDigest(m)` = b64u(sha256(strictCanonical({d: "atlas-pca/intent-map/v1", m}))).
pub fn intent_map_digest(m: &Value) -> Result<String, String> {
    hash_canonical_strict(&json!({"d": INTENT_MAP_DOMAIN, "m": m}))
        .ok_or_else(|| "intentMapDigest: the map is not canonicalizable".to_string())
}

/// `signIntentMapAttestation(map, key, signedAt, suite)`: a detached signature over the map's digest.
pub fn sign_intent_map_attestation(map: &Value, key: &KeyPair, signed_at: i64, s: &Suite) -> Result<Value, String> {
    if let Some(e) = intent_map_shape_error(map) {
        return Err(format!("signIntentMapAttestation: {e}"));
    }
    if !(0..=MAX_SAFE as i64).contains(&signed_at) {
        return Err("signIntentMapAttestation: signedAt must be a non-negative safe integer".into());
    }
    let body = json!({"v": 1, "map_digest": intent_map_digest(map)?, "intent_ref": map["intent_ref"], "signer": key.public, "signed_at": signed_at});
    sign_artifact(INTENT_MAP_SIG_DOMAIN, &body, key, s)
}

fn verdict(r: Result<(), String>) -> Value {
    match r {
        Ok(()) => json!({"ok": true}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    }
}

fn pin_for<'a>(pins: Option<&'a Value>, who: &'a str) -> Option<(&'a str, &'a Value)> {
    pins.and_then(|p| p.get(who)).map(|p| (who, p))
}

/// `verifyIntentMapAttestation(a, map, opts)`: well-formed, the signature valid (a PQ key only under `pq_pins`
/// `{ed25519 b64u: PQ public key}`), and, when `map` is given, its digest and `intent_ref` match. `{ok}` or `{ok: false, reason}`.
pub fn verify_intent_map_attestation(a: &Value, map: Option<&Value>, expected_signer: Option<&str>, pq_pins: Option<&Value>) -> Value {
    verdict((|| -> Result<(), String> {
        let o = match a.as_object() {
            Some(o) if o.get("v").and_then(Value::as_i64) == Some(1) => o,
            _ => return Err("not an intent map attestation v1".to_string()),
        };
        let b32 = |v: Option<&Value>| v.and_then(Value::as_str).is_some_and(|x| crate::decode_b64u_strict(x, Some(32)).is_some());
        if !b32(o.get("map_digest")) {
            return Err("map_digest is not canonical base64url (32 bytes)".into());
        }
        if !(matches!(o.get("intent_ref"), Some(Value::Null)) || b32(o.get("intent_ref"))) {
            return Err("intent_ref must be null or canonical base64url (32 bytes)".into());
        }
        if !b32(o.get("signer")) {
            return Err("signer is not canonical base64url (32 bytes)".into());
        }
        if !is_int(o.get("signed_at")).is_some_and(|f| f >= 0.0) {
            return Err("signed_at must be a non-negative safe integer".into());
        }
        let signer = o["signer"].as_str().unwrap_or_default();
        if expected_signer.is_some_and(|e| e != signer) {
            return Err("signer mismatch".into());
        }
        if let Some(e) = crate::intent_suite::suite_shape_error(o, "attestation", "", "sig") {
            return Err(e);
        }
        if let Some(m) = map {
            if let Some(e) = intent_map_shape_error(m) {
                return Err(e);
            }
            if intent_map_digest(m)? != o["map_digest"].as_str().unwrap_or_default() {
                return Err("map digest mismatch".into());
            }
            if m.get("intent_ref") != o.get("intent_ref") {
                return Err("intent_ref mismatch".into());
            }
        }
        let mut body = Map::new();
        for k in ["v", "map_digest", "intent_ref", "signer", "signed_at"] {
            body.insert(k.into(), o[k].clone());
        }
        if !crate::intent_suite::bind_suite_fields(&mut body, o.get("alg"), o.get("pq_pk"))? {
            return Err("malformed intent map attestation: pq_pk missing".into());
        }
        let msg = crate::intent_suite::domain_message(INTENT_MAP_SIG_DOMAIN, body)
            .ok_or("malformed intent map attestation: not canonicalizable")?;
        match crate::intent_suite::verify_pinned_suite(
            o.get("alg"),
            signer,
            o.get("pq_pk"),
            &msg,
            o.get("sig"),
            o.get("pq_sig"),
            pin_for(pq_pins, signer),
        )? {
            true => Ok(()),
            false => Err("bad signature".into()),
        }
    })())
}

/// `verifyIntentAnchor(receipt, guardianPublic, instanceId, pins)`: the artifact `{kind, digest}` is included at `index` under
/// a guardian-signed head of this instance's intent log. `{ok}` or `{ok: false, reason}`.
pub fn verify_intent_anchor(r: &Value, guardian_public: &str, instance_id: &str, pins: Option<&Value>) -> Value {
    verdict((|| -> Result<(), String> {
        let kind = r.get("kind").and_then(Value::as_str).filter(|k| ANCHOR_KINDS.contains(k)).ok_or("unknown anchor kind")?;
        let digest = r
            .get("digest")
            .and_then(Value::as_str)
            .filter(|d| crate::decode_b64u_strict(d, Some(32)).is_some())
            .ok_or("digest is not canonical base64url (32 bytes)")?;
        let h = r.get("signed_tree_head").ok_or("malformed anchor receipt: signed_tree_head missing")?;
        if h.get("principal").and_then(Value::as_str) != Some(INTENT_ANCHOR_LOG)
            || h.get("instance_id").and_then(Value::as_str) != Some(instance_id)
        {
            return Err("not a head of this instance intent log".into());
        }
        if !crate::ledger::verify_tree_head_pinned(h, guardian_public, None, pins) {
            return Err("tree head signature invalid".into());
        }
        let proof = r.get("proof").and_then(Value::as_object).ok_or("malformed anchor receipt: proof missing")?;
        if proof.get("index") != r.get("index") || proof.get("size") != h.get("size") {
            return Err("proof does not match the head".into());
        }
        let commit = crate::evidence::anchor_commit(&json!(kind), &json!(digest))?;
        match crate::verify_inclusion(h.get("root").and_then(Value::as_str).unwrap_or_default(), Some(proof), &json!(commit)) {
            true => Ok(()),
            false => Err("artifact is not included under the signed head".into()),
        }
    })())
}

// ---- principal re-approval, registry key ---------------------------------------------------------------------------------------

/// `signReapproval({grantId, record, principalSecret})`: the principal approves one evolution step for one grant
/// (`grant_id` is `grant.id`; `key` the key that minted it). `{v, kind, grant, verb, diff, sig: {alg: "ed25519", value}}`.
pub fn sign_reapproval(grant_id: &str, record: &Value, key: &KeyPair) -> Result<Value, String> {
    let verb = record.get("verb").and_then(Value::as_str).ok_or("signReapproval: record.verb must be a string")?;
    let diff = crate::actions_registry::evolution_diff_digest(record).ok_or("signReapproval: the evolution record has no diff digest")?;
    let body = json!({"v": 1, "kind": REAPPROVAL_KIND, "grant": grant_id, "verb": verb, "diff": diff});
    let mut msg = REAPPROVAL_DOMAIN.as_bytes().to_vec();
    msg.extend(canonicalize_strict(&body)?.into_bytes());
    let (value, _) = sign_with_suite(&Suite::default(), Some(key), &msg)?;
    let mut out = body;
    out["sig"] = json!({"alg": "ed25519", "value": value});
    Ok(out)
}

/// `registryKeyOf(kid, key, suite)`: the pinned registry key entry `{kid, alg, pk, pq_pk?}` of a signer.
pub fn registry_key_of(kid: &str, key: &KeyPair, s: &Suite) -> Result<Value, String> {
    let alg = s.alg.unwrap_or("ed25519");
    let suite = crate::intent_suite::suite_of(Some(&json!(alg)))?;
    let mut out = json!({"kid": kid, "alg": suite.alg, "pk": key.public});
    if suite.needs_pq_pk {
        out["pq_pk"] = json!(s.pq.ok_or_else(|| format!("registryKeyOf: {alg} needs a post-quantum key pair"))?.public);
    }
    Ok(out)
}

// ---- accumulator receipts, sequencer key sets ---------------------------------------------------------------------------------

const RECEIPT_FIELDS: [&str; 14] =
    ["v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid", "ledger"];

/// `signAccReceipt(body, sequencerSecret, suite)`: the receipt body (14 members; `ledger` is `{index, head}`) plus the
/// sequencer's identity as `signer`, signed under `"atlas-pca/acc-receipt/v1\0"`. The result must pass the verifier's shape check.
pub fn sign_acc_receipt(body: &Value, sequencer: &KeyPair, s: &Suite) -> Result<Value, String> {
    let mut m = Map::new();
    for k in RECEIPT_FIELDS {
        m.insert(k.into(), body.get(k).cloned().ok_or_else(|| format!("signAccReceipt: {k} required"))?);
    }
    let l = m["ledger"].clone();
    m.insert("ledger".into(), json!({"index": l.get("index").ok_or("signAccReceipt: ledger.index required")?, "head": l.get("head").ok_or("signAccReceipt: ledger.head required")?}));
    m.insert("signer".into(), json!(sequencer.public));
    let out = sign_artifact(crate::intent_acc::ACC_RECEIPT_DOMAIN, &Value::Object(m), sequencer, s)?;
    match crate::intent_acc::acc_receipt_shape_error(&out) {
        Some(e) => Err(format!("signAccReceipt: {e}")),
        None => Ok(out),
    }
}

/// `verifyAccReceiptSignature(r, expectedSigner, pin)`: total (`false` on any failure); `pq_pins` as in
/// [`verify_intent_map_attestation`].
pub fn verify_acc_receipt_signature(r: &Value, expected_signer: &str, pq_pins: Option<&Value>) -> bool {
    crate::intent_acc::verify_acc_receipt_signature(r, expected_signer, pin_for(pq_pins, expected_signer)).unwrap_or(false)
}

/// `signSequencerKeySet(body, rootSecret, suite)`: `{v, kind, version, issued_at, keys}` plus `sequencer` = the root's identity,
/// signed under `"atlas-pca/sequencer-keys/v1\0"`. The result must pass the verifier's shape check.
pub fn sign_sequencer_key_set(body: &Value, root: &KeyPair, s: &Suite) -> Result<Value, String> {
    let mut m = Map::new();
    for k in ["v", "kind", "version", "issued_at", "keys"] {
        m.insert(k.into(), body.get(k).cloned().ok_or_else(|| format!("signSequencerKeySet: {k} required"))?);
    }
    m.insert("sequencer".into(), json!(root.public));
    let out = sign_artifact(crate::intent_acc::SEQUENCER_KEYS_DOMAIN, &Value::Object(m), root, s)?;
    match crate::intent_acc::sequencer_key_set_shape_error(&out) {
        Some(e) => Err(format!("signSequencerKeySet: {e}")),
        None => Ok(out),
    }
}

/// `verifySequencerKeySet(k, root, rootPqPk)`: total (`false` on any failure).
pub fn verify_sequencer_key_set(k: &Value, root: &str, root_pq_pk: Option<&str>) -> bool {
    let pq = root_pq_pk.map(|p| json!(p));
    crate::intent_acc::verify_sequencer_key_set(k, root, pq.as_ref()).unwrap_or(false)
}

// ---- registry documents and evolution records ----------------------------------------------------------------------------------

/// `signRegistryDoc(domain, body, kid, secret, suite)`: sign `body` under `domain` as a registry key: `{alg, kid, value, pq_value?}` over
/// `domain || strictCanonical(body)` (`kid` names the pinned key entry; the suite is pinned by that entry).
pub fn sign_registry_doc_value(domain: &str, body: &Value, kid: &str, key: &KeyPair, s: &Suite) -> Result<Value, String> {
    let mut msg = domain.as_bytes().to_vec();
    msg.extend(canonicalize_strict(body)?.into_bytes());
    let (value, pq_value) = sign_with_suite(s, Some(key), &msg)?;
    let alg = crate::intent_suite::suite_of(Some(&json!(s.alg.unwrap_or("ed25519"))))?.alg;
    let mut out = json!({"alg": alg, "kid": kid, "value": value});
    if let Some(p) = pq_value {
        out["pq_value"] = json!(p);
    }
    Ok(out)
}

/// `signEvolutionRecord(record, kid, secret, suite)`: sign an evolution record as the registry. An invalid unsigned record is refused,
/// never signed.
pub fn sign_evolution_record(rec: &Value, kid: &str, key: &KeyPair, s: &Suite) -> Result<Value, String> {
    if let Some(bad) = crate::actions_registry::evolution_record_error(rec, false) {
        return Err(format!("signEvolutionRecord: {bad}"));
    }
    let sig = sign_registry_doc_value(crate::actions_registry::EVOLUTION_DOMAIN, rec, kid, key, s)?;
    let mut out = rec.clone();
    out["sig"] = sig;
    Ok(out)
}
