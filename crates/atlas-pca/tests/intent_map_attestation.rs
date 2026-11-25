//! The signed intent-map attestation (sign, verify, the shape check) and the intent-anchor receipt check: an artifact is anchored
//! when it is included under a guardian-signed head of this instance's intent log.
use atlas_pca::agent::{sign_artifact, KeyPair, Suite};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::sign_parity::*;

fn digest(b: u8) -> String {
    atlas_pca::kem::encode_hybrid_public_key(&[b; 32])
}

fn map() -> Value {
    json!({"v": 1, "kind": "pca-intent-map", "intent_ref": digest(7), "metrics": {"fidelity_est_ppm": 900000, "residual_risk_ppm": 12}})
}

fn reason(v: &Value) -> &str {
    v["reason"].as_str().unwrap_or("")
}

#[test]
fn an_attestation_binds_the_map_and_its_signer() {
    let (key, other) = (KeyPair::from_seed(&[1; 32]), KeyPair::from_seed(&[2; 32]));
    let m = map();
    let a = sign_intent_map_attestation(&m, &key, 1_800_000_000_000, &Suite::default()).expect("signed");
    assert_eq!((a["signer"].as_str(), a["map_digest"].as_str(), &a["intent_ref"]), (Some(key.public.as_str()), Some(intent_map_digest(&m).unwrap().as_str()), &m["intent_ref"]));
    assert_eq!(verify_intent_map_attestation(&a, Some(&m), Some(&key.public), None), json!({"ok": true}));
    assert_eq!(verify_intent_map_attestation(&a, None, None, None), json!({"ok": true}), "detached: the signature alone");

    assert_eq!(reason(&verify_intent_map_attestation(&a, Some(&m), Some(&other.public), None)), "signer mismatch");
    let mut changed = m.clone();
    changed["metrics"]["residual_risk_ppm"] = json!(13);
    assert_eq!(reason(&verify_intent_map_attestation(&a, Some(&changed), None, None)), "map digest mismatch");
    let mut forged = a.clone();
    forged["signed_at"] = json!(1_800_000_000_001i64);
    assert_eq!(reason(&verify_intent_map_attestation(&forged, Some(&m), None, None)), "bad signature");
    let mut resigned = a.clone();
    resigned["signer"] = json!(other.public);
    assert_eq!(reason(&verify_intent_map_attestation(&resigned, Some(&m), None, None)), "bad signature");
    assert_eq!(reason(&verify_intent_map_attestation(&json!({"v": 2}), None, None, None)), "not an intent map attestation v1");
}

#[test]
fn a_malformed_map_is_not_signed() {
    let key = KeyPair::from_seed(&[1; 32]);
    assert_eq!(intent_map_shape_error(&map()), None);
    let mut null_ref = map();
    null_ref["intent_ref"] = Value::Null;
    assert_eq!(intent_map_shape_error(&null_ref), None);
    for (edit, why) in [
        (json!({"kind": "other"}), "not an intent map v1"),
        (json!({"intent_ref": "short"}), "intent_ref must be null or canonical base64url (32 bytes)"),
        (json!({"metrics": {"fidelity_est_ppm": 1000001, "residual_risk_ppm": 0}}), "metrics.fidelity_est_ppm must be an integer in [0, 1e6]"),
        (json!({"metrics": {"fidelity_est_ppm": 1, "residual_risk_ppm": -1}}), "metrics.residual_risk_ppm must be a non-negative integer"),
        (json!({"metrics": 5}), "metrics must be an object"),
    ] {
        let mut m = map();
        for (k, v) in edit.as_object().unwrap() {
            m[k.as_str()] = v.clone();
        }
        assert_eq!(intent_map_shape_error(&m).as_deref(), Some(why));
        assert!(sign_intent_map_attestation(&m, &key, 1, &Suite::default()).is_err(), "{why}");
    }
    assert!(sign_intent_map_attestation(&map(), &key, -1, &Suite::default()).is_err(), "a negative time");
}

#[test]
fn an_anchor_receipt_needs_inclusion_under_a_head_of_this_instance_signed_by_the_guardian() {
    let (guardian, stranger) = (KeyPair::from_seed(&[3; 32]), KeyPair::from_seed(&[4; 32]));
    let d = digest(9);
    let commit = atlas_pca::evidence::anchor_commit(&json!("map"), &json!(d)).unwrap();
    let leaves = vec![json!("another-entry"), json!(commit), json!("a-third-entry")];
    let root = atlas_pca::merkle_root(&leaves).unwrap();
    let head_by = |k: &KeyPair, instance: &str, principal: &str| {
        let body = json!({"instance_id": instance, "principal": principal, "size": 3, "root": root, "prev_root": digest(0), "timestamp": 1_800_000_000_000i64});
        let mut h = sign_artifact("atlas-pca/sth/v1\0", &body, k, &Suite::default()).expect("head");
        h["guardian"] = json!(k.public);
        h
    };
    let receipt = |head: Value, index: usize| json!({"kind": "map", "digest": d, "index": index, "signed_tree_head": head, "proof": atlas_pca::grants::merkle_proof(&leaves, &json!(index)).unwrap()});
    let good = receipt(head_by(&guardian, "ins_1", "pca-intent:v1"), 1);
    assert_eq!(verify_intent_anchor(&good, &guardian.public, "ins_1", None), json!({"ok": true}));

    assert_eq!(reason(&verify_intent_anchor(&good, &guardian.public, "ins_2", None)), "not a head of this instance intent log");
    assert_eq!(reason(&verify_intent_anchor(&receipt(head_by(&guardian, "ins_1", "another-log"), 1), &guardian.public, "ins_1", None)), "not a head of this instance intent log");
    assert_eq!(reason(&verify_intent_anchor(&receipt(head_by(&stranger, "ins_1", "pca-intent:v1"), 1), &guardian.public, "ins_1", None)), "tree head signature invalid");
    // the proof of another leaf does not include this artifact
    assert_eq!(reason(&verify_intent_anchor(&receipt(head_by(&guardian, "ins_1", "pca-intent:v1"), 0), &guardian.public, "ins_1", None)), "artifact is not included under the signed head");
    let mut other_kind = good.clone();
    other_kind["kind"] = json!("receipt");
    assert_eq!(reason(&verify_intent_anchor(&other_kind, &guardian.public, "ins_1", None)), "artifact is not included under the signed head");
    let mut unknown = good.clone();
    unknown["kind"] = json!("anything");
    assert_eq!(reason(&verify_intent_anchor(&unknown, &guardian.public, "ins_1", None)), "unknown anchor kind");
}
