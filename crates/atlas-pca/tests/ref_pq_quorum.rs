//! Differential replay of test-data/ref-pq-threshold-quorum.json.gz (written by the TypeScript reference): quorum sets (build and
//! load), the quorum message and action digest, per-signer shares (Ed25519 hybrids, ML-DSA-65 and ML-DSA-87; SLH-DSA shares are
//! verified as data), proof assembly and verification, rotation certificates and chains, the fork check and proof size accounting.
//! A case the reference refuses must be refused here.
mod common;
use atlas_pca::agent::{KeyPair, PqKeyPair};
use atlas_pca::pq_quorum::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use common::replay::{replay, thrown};

fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    v.get("$bytes").and_then(Value::as_str).map(common::b64d)
}

fn set_result(set: Option<Value>) -> Value {
    set.map_or_else(|| json!({"ok": false, "reason": "bad-set"}), |s| json!({"ok": true, "set": s}))
}

/// The key material of a signing case: the Ed25519 seed (`edSecret`) and the ML-DSA key generation seed of the signer's family
/// (`mlDsa` for ML-DSA-65, `mlDsa87` for ML-DSA-87).
fn keys(set: &Value, index: &Value, k: &Value) -> (Option<KeyPair>, Option<PqKeyPair>) {
    let at = index.as_u64().or_else(|| index.as_str().and_then(|s| s.parse().ok())).unwrap_or(u64::MAX) as usize;
    let alg = set["signers"].get(at).and_then(|e| e["alg"].as_str()).unwrap_or("");
    let family = if alg.contains("ml-dsa-87") {
        Some(("ML-DSA-87", "mlDsa87"))
    } else if alg.contains("ml-dsa-65") {
        Some(("ML-DSA-65", "mlDsa"))
    } else {
        None
    };
    let ed = k.get("edSecret").and_then(Value::as_str).and_then(|s| KeyPair::from_seed_b64u(s).ok());
    let pq = family.and_then(|(f, member)| PqKeyPair::from_seed(f, &atlas_pca::decode_b64u_strict(k.get(member)?.as_str()?, None)?).ok());
    (ed, pq)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({"PQ_QUORUM_MAX_SIGNERS": PQ_QUORUM_MAX_SIGNERS, "PQ_QUORUM_MAX_CHAIN": PQ_QUORUM_MAX_CHAIN}),
        // the diversity commitment defaults to 0 when the argument is absent
        "buildQuorumSet" => set_result(build_quorum_set(&a[0], &a[1], a.get(2).unwrap_or(&json!(0)))),
        "loadQuorumSet" => set_result(load_quorum_set(&a[0])),
        "quorumMessage" => {
            quorum_message(&a[0], &a[1], &a[2]).map_or_else(thrown, |m| json!({"$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(m)}))
        }
        // the reference hashes a string as its UTF-8 bytes
        "quorumActionDigest" => match bytes_of(&a[0]).or_else(|| a[0].as_str().map(|s| s.as_bytes().to_vec())) {
            Some(m) => json!(quorum_action_digest(&m)),
            None => thrown("not bytes"),
        },
        "signQuorumShare" => {
            let (ed, pq) = keys(&a[0], &a[1], &a[4]);
            sign_quorum_share(&a[0], &a[1], &a[2], &a[3], ed.as_ref(), pq.as_ref()).unwrap_or_else(thrown)
        }
        "assembleQuorumProof" => assemble_quorum_proof(&a[0], &a[1]).unwrap_or_else(thrown),
        "verifyQuorum" => verify_quorum(&a[0]),
        "verifyQuorumApproval" => json!(bytes_of(&a[2]).is_some_and(|m| verify_quorum_approval(&a[0], &a[1], &m, &a[3], a.get(4)))),
        "rotationActionDigest" => rotation_action_digest(&a[0], &a[1]).map_or_else(thrown, Value::String),
        "signRotationShare" => {
            let (ed, pq) = keys(&a[0], &a[1], &a[4]);
            sign_rotation_share(&a[0], &a[1], &a[2], &a[3], ed.as_ref(), pq.as_ref()).unwrap_or_else(thrown)
        }
        "buildRotationCert" => build_rotation_cert(&a[0], &a[1], &a[2], &a[3]).unwrap_or_else(thrown),
        "verifyRotationChain" => verify_rotation_chain(&a[0], &a[1], &a[2]),
        "isRotationFork" => json!(is_rotation_fork(&a[0], &a[1])),
        "quorumProofSize" => quorum_proof_size(&a[0], a.get(1)).unwrap_or_else(thrown),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn the_pq_quorum_matches_the_reference() {
    // 1 quorum message is asked of a lone surrogate
    replay("pq-threshold-quorum", 389, 1, run);
}
