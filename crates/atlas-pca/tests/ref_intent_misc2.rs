//! Differential replay of test-data/ref-intent-misc2.json.gz (written by the TypeScript reference): the strict-artifact helpers, the signed
//! "ask the principal" question and its RFC 9457 problem, the classifier verdict wire / policy / quorum decision / judge attestation gate, the
//! digests of accumulator receipts and sequencer key sets and the monitor helpers. The signers (`signIntentRequired`,
//! `signClassifierVerdict`, `signAccReceipt`, `signSequencerKeySet`) are replayed by ref_core_gaps.rs and the session-store half
//! (`accContextFor`, `admit`) by ref_intent_admit.rs: the totals of the whole corpus are asserted here, and those 70 cases are left to them.
//! A reference refusal must be a refusal here. A case whose value is a non-finite double (`{"$num"}`) is refused by the strict profile of the
//! reference; a JSON value cannot carry one, so those cases are counted as not run, as are the two with a lone surrogate. The one receipt
//! the reference accepts ONLY through the legacy `allowUnboundPq` option (a post-quantum signature with no pinned key) must be REFUSED here
//! (count asserted).
mod common;
use std::collections::BTreeMap;

use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::intent_misc2::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay_cases, skip, thrown};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn enc(b: &[u8]) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

fn key(v: &Value) -> KeyPair {
    KeyPair::from_seed_b64u(text(&v["$bytes"])).unwrap()
}

/// A non-finite double marker `{"$num": "NaN" | "Infinity" | "-Infinity"}`.
fn marker(v: &Value) -> Option<f64> {
    match v.as_object().filter(|m| m.len() == 1)?.get("$num")?.as_str()? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

fn has_marker(v: &Value) -> bool {
    marker(v).is_some()
        || match v {
            Value::Array(a) => a.iter().any(has_marker),
            Value::Object(m) => m.values().any(has_marker),
            _ => false,
        }
}

/// The signing suite a case names: `null` (ed25519) or `{alg, pqSeed?}`.
fn with_suite<R>(spec: &Value, f: impl FnOnce(&Suite) -> R) -> Result<R, String> {
    let spec = Some(spec).filter(|s| !s.is_null());
    let alg = spec.and_then(|s| s["alg"].as_str());
    let pq = match spec.filter(|_| alg != Some("ed25519")) {
        Some(s) => match s.get("pqSeed") {
            Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(text(&seed["$bytes"]))).unwrap()),
            None => return Err("mlDsa65Keygen: the seed is required".into()),
        },
        None => None,
    };
    Ok(f(&Suite { alg, pq: pq.as_ref() }))
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

fn run(f: &str, a: &[Value]) -> Value {
    let marked = has_marker(&Value::Array(a.to_vec()));
    // a non-finite double inside a value the strict profile hashes or signs: the reference refuses it, a JSON value cannot carry one
    if marked
        && matches!(
            f,
            "artifactMessage" | "signArtifact" | "artifactRef" | "classifierContentDigest" | "classifierVerdictRef" | "distinctKey"
        )
    {
        return skip("a non-finite double is not a JSON value");
    }
    match f {
        "constants" => constants(),
        "isPathSegment" => json!(is_path_segment_value(&a[0])),
        "isPlainObject" => json!(marker(&a[0]).is_none() && is_plain_object(&a[0])),
        "isSafeInt" | "isClock" => json!(marker(&a[0]).is_none() && is_safe_int(&a[0])),
        "isScalar" => json!(marker(&a[0]).is_none() && is_scalar_value(&a[0])),
        "scalarEq" => match (marker(&a[0]), marker(&a[1])) {
            (None, None) => {
                json!(atlas_pca::canonicalize(&a[0]) == atlas_pca::canonicalize(&a[1]) && !a[0].is_array() && !a[0].is_object())
            }
            (Some(x), Some(y)) => json!(x == y),
            _ => json!(false),
        },
        "utf8Len" => json!(utf8_len(text(&a[0]))),
        "isBoundedString" => json!(is_bounded_string(&a[0], marker(&a[1]).or(a[1].as_f64()).unwrap())),
        "isDigest" => json!(is_digest(&a[0])),
        "closedMembers" => closed_members_value(&a[0], &strs(&a[1]), &strs(&a[2]), a[3].as_str()),
        "pinPqOk" => json!(pin_pq_ok_value(&a[0])),
        "artifactSuiteError" => artifact_suite_error_value(&a[0]),
        "artifactMessage" => artifact_message_bytes(text(&a[0]), &a[1]).map(|b| enc(&b)).unwrap_or_else(thrown),
        "signArtifact" => with_suite(&a[3], |s| atlas_pca::agent::sign_artifact(text(&a[0]), &a[1], &key(&a[2]), s))
            .and_then(|r| r)
            .unwrap_or_else(thrown),
        "verifyArtifactSig" => json!(verify_artifact_sig_value(text(&a[0]), &a[1], &a[2])),
        "artifactRef" => artifact_ref_value(text(&a[0]), text(&a[1]), &a[2]).map(Value::String).unwrap_or_else(thrown),
        "publicKeyB64u" => json!(key(&a[0]).public),
        "resolveParamPath" => resolve_param_path_value(&a[0], &a[1]),
        "isParamPath" => json!(is_param_path_value(&a[0])),
        "setNested" => set_nested_value(&a[0]["root"], text(&a[0]["path"]), &a[0]["value"]),
        "ownGet" => own_get(&a[0], text(&a[1])),
        "nullRecord" => json!({}),
        "intentActionDigest" => atlas_pca::intent_kit::jit::intent_action_digest(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "cellCoordsError" => cell_coords_error_value(&a[0]),
        "intentRequiredShapeError" => intent_required_shape_error_value(&a[0], a[1].get("signed") != Some(&json!(false))),
        "verifyIntentRequired" => atlas_pca::wallet_channel::verify_intent_required(&a[0], Some(&a[1]), Some(&a[2])),
        "verifyIntentRequiredAt" => verify_intent_required_at(&a[0], &a[1], &a[2]),
        "intentProblem" => intent_problem(&a[0], &a[1]).unwrap_or_else(thrown),
        "validateClassifierVerdictWire" => validate_classifier_verdict_wire(&a[0]),
        "classifierContentDigest" => classifier_content_digest(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "classifierVerdictRef" => classifier_verdict_ref(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "validateClassifierPolicy" => validate_classifier_policy(&a[0]),
        "classifierCheckActive" => json!(classifier_check_active(&a[0])),
        "decideClassifierDimensions" => decide_classifier_dimensions_value(&a[0]),
        "verifyClassifierAttestation" => verify_classifier_attestation(&a[0], &a[1], &a[2]),
        "monitorStates" => monitor_states_value(&a[0]),
        "monitorInitialState" => json!(monitor_initial_state(&a[0])),
        "distinctKey" => distinct_key(&a[0]).map_or(Value::Null, Value::String),
        "sortedDistinct" => json!(sorted_distinct(&strs(&a[0]).into_iter().map(String::from).collect::<Vec<_>>())),
        "accReceiptDigest" => acc_receipt_digest_value(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "accReceiptCoreDigest" => acc_receipt_core_digest(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "verifyReceiptSignature" => {
            let pin = Some(&a[2]).filter(|p| !p.is_null());
            if unbound(pin) {
                return skip("the legacy allowUnboundPq acceptance is not ported");
            }
            json!(atlas_pca::sign_parity::verify_acc_receipt_signature(&a[0], text(&a[1]), pin.and_then(|p| p.get("pqPins"))))
        }
        "sequencerKeySetDigest" => sequencer_key_set_digest_value(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "verifyKeySet" => json!(atlas_pca::sign_parity::verify_sequencer_key_set(&a[0], text(&a[1]), a[2].as_str())),
        other => panic!("unhandled corpus function {other}"),
    }
}

fn unbound(pin: Option<&Value>) -> bool {
    pin.and_then(|p| p.get("allowUnboundPq")) == Some(&json!(true))
}

const ELSEWHERE: [&str; 6] =
    ["signIntentRequired", "signClassifierVerdict", "signAccReceipt", "signSequencerKeySet", "accContextFor", "admit"];

#[test]
fn intent_misc2_replay() {
    let cases = common::ref_cases_seeded("intent-misc2");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"]).to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("constants", 1),
        ("isPathSegment", 16),
        ("isPlainObject", 8),
        ("isSafeInt", 12),
        ("isScalar", 16),
        ("isClock", 12),
        ("scalarEq", 11),
        ("utf8Len", 7),
        ("isBoundedString", 12),
        ("isDigest", 12),
        ("closedMembers", 8),
        ("pinPqOk", 6),
        ("artifactSuiteError", 12),
        ("artifactMessage", 10),
        ("signArtifact", 8),
        ("verifyArtifactSig", 18),
        ("artifactRef", 8),
        ("publicKeyB64u", 2),
        ("resolveParamPath", 25),
        ("isParamPath", 25),
        ("setNested", 14),
        ("ownGet", 11),
        ("nullRecord", 1),
        ("intentActionDigest", 6),
        ("cellCoordsError", 26),
        ("intentRequiredShapeError", 90),
        ("signIntentRequired", 8),
        ("verifyIntentRequired", 26),
        ("verifyIntentRequiredAt", 26),
        ("intentProblem", 42),
        ("classifierContentDigest", 12),
        ("signClassifierVerdict", 7),
        ("validateClassifierVerdictWire", 26),
        ("classifierVerdictRef", 5),
        ("validateClassifierPolicy", 42),
        ("classifierCheckActive", 11),
        ("decideClassifierDimensions", 44),
        ("verifyClassifierAttestation", 11),
        ("monitorStates", 13),
        ("monitorInitialState", 13),
        ("distinctKey", 18),
        ("sortedDistinct", 7),
        ("signAccReceipt", 16),
        ("accReceiptDigest", 4),
        ("accReceiptCoreDigest", 4),
        ("verifyReceiptSignature", 8),
        ("signSequencerKeySet", 15),
        ("sequencerKeySetDigest", 3),
        ("verifyKeySet", 8),
        ("accContextFor", 13),
        ("admit", 11),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 770);

    // the legacy unbound-PQ acceptance is refused here (one case)
    let legacy: Vec<&Value> = cases.iter().filter(|c| text(&c["fn"]) == "verifyReceiptSignature" && unbound(Some(&c["args"][2]))).collect();
    assert_eq!(legacy.len(), 1);
    for c in legacy {
        assert_eq!(c["out"], json!(true), "the reference accepts it only through allowUnboundPq");
        let a = c["args"].as_array().unwrap();
        assert_eq!(atlas_pca::sign_parity::verify_acc_receipt_signature(&a[0], text(&a[1]), None), false);
    }

    let mine: Vec<Value> = cases.into_iter().filter(|c| !ELSEWHERE.contains(&text(&c["fn"]))).collect();
    // 2 lone surrogates, 6 non-finite doubles in a hashed value, the legacy unbound-PQ receipt
    replay_cases("intent-misc2", mine, 700, 2 + 6 + 1, run);
}
