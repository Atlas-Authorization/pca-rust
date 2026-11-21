//! Differential replay of the WebAuthn step-up binding against the TypeScript reference (test-data/ref-webauthn-py.json.gz):
//! COSE_Key reading, authenticator data, step-up / approval challenges, the payment binding and assertion verification
//! (result and the sign-count regression hook). Texts compare exactly, except JavaScript runtime TypeErrors (refusal only).
//! Inputs the typed native API cannot express (a non-bytes value where bytes are required, a non-string render digest, a
//! non-object PCActn) are skipped.
mod common;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::webauthn::*;
use std::cell::RefCell;

fn bytes(v: &Value) -> Option<Vec<u8>> {
    v.get("$bytes").and_then(Value::as_str).map(common::b64d)
}

fn b64e(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A reference TypeError has no native wording; any refusal stands for it.
fn runtime(msg: &str) -> bool {
    msg.contains("Cannot read properties of") || msg.contains("Cannot destructure")
}

fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if w == g || runtime(w) => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(want) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

enum Src {
    Bytes(Vec<u8>),
    Str(String),
    Actn(atlas_pca::serde_json::Map<String, Value>),
}

fn source(v: &Value) -> Option<Src> {
    match v {
        Value::String(s) => Some(Src::Str(s.clone())),
        Value::Object(m) if m.contains_key("$bytes") => bytes(v).map(Src::Bytes),
        Value::Object(m) => Some(Src::Actn(m.clone())),
        _ => None,
    }
}

fn with_src<T>(s: &Src, f: impl FnOnce(StepUpSource) -> T) -> T {
    f(match s {
        Src::Bytes(b) => StepUpSource::Digest(b),
        Src::Str(s) => StepUpSource::DigestB64u(s),
        Src::Actn(m) => StepUpSource::Actn(m),
    })
}

fn verify_case(args: &[Value]) -> Option<Value> {
    let (a, e) = (&args[0], &args[1]);
    let (ad, cd, sg) = (bytes(&a["authenticator_data"])?, bytes(&a["client_data_json"])?, bytes(&a["signature"])?);
    let pk_bytes = bytes(&a["public_key"]);
    let null = Value::Null;
    let public_key = match &pk_bytes {
        Some(b) => CredentialPublicKey::Cose(b),
        None => CredentialPublicKey::Jwk(a.get("public_key").unwrap_or(&null)),
    };
    let ch_bytes = bytes(&e["expected_challenge"]);
    let expected_challenge = match (&ch_bytes, e.get("expected_challenge").and_then(Value::as_str)) {
        (Some(b), _) => Some(Challenge::Bytes(b)),
        (None, Some(s)) => Some(Challenge::B64u(s)),
        _ => None,
    };
    // non-string allowlist entries never equal an origin
    let origins: Vec<&str> = e["origins"].as_array().map(|o| o.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let seen = RefCell::new(Vec::new());
    let hook = |stored: u32, reported: u32| seen.borrow_mut().push(json!({ "storedSignCount": stored, "reportedSignCount": reported }));
    let truthy = |v: &Value| !matches!(v, Value::Null | Value::Bool(false)) && v != &json!(0) && v != &json!("");
    // the corpus loader stands a sentinel in for a lone surrogate; the reference hashes the UTF-8 of the id, where it is U+FFFD
    let rp_id = e["rp_id"].as_str().unwrap_or("").replace(common::LONE, "\u{fffd}");
    let x = VerifyExpectations {
        expected_challenge,
        rp_id: &rp_id,
        origins: &origins,
        require_uv: truthy(&e["require_uv"]),
        require_low_s: e["require_low_s"] == json!(true),
        stored_sign_count: e.get("stored_sign_count").map(|v| v.as_f64().unwrap_or(f64::NAN)),
        on_sign_count_regression: Some(&hook),
        reject_cross_origin: e["reject_cross_origin"] != json!(false),
        payment: e.get("payment"),
    };
    let result = verify_assertion(&Assertion { authenticator_data: &ad, client_data_json: &cd, signature: &sg, public_key }, &x);
    Some(json!({ "result": result, "regression": seen.into_inner() }))
}

#[test]
fn webauthn_replays_the_reference() {
    let (mut fails, mut ran, mut skipped) = (Vec::new(), 0, 0);
    for c in common::ref_cases("webauthn-py") {
        let (name, args, want) = (c["name"].as_str().unwrap().to_string(), c["args"].as_array().unwrap().clone(), &c["out"]);
        let r: Option<Result<(), String>> = match c["fn"].as_str().unwrap() {
            "constants" => Some(same(
                want,
                Ok(
                    json!({ "MAX_AUTHENTICATOR_DATA_BYTES": MAX_AUTHENTICATOR_DATA_BYTES, "MAX_CLIENT_DATA_BYTES": MAX_CLIENT_DATA_BYTES, "MAX_SIGNATURE_BYTES": MAX_SIGNATURE_BYTES }),
                ),
            )),
            "coseKeyToJwk" => bytes(&args[0]).map(|b| same(want, cose_key_to_jwk(&b))),
            "parseAuthenticatorData" => bytes(&args[0]).map(|b| {
                let got = parse_authenticator_data(&b)
                    .map_or(Value::Null, |p| json!({ "rpIdHash": { "$bytes": b64e(&p.rp_id_hash) }, "flags": p.flags.to_json(), "signCount": p.sign_count }));
                same(want, Ok(got))
            }),
            "buildStepUpChallenge" => source(&args[0]).map(|s| same(want, with_src(&s, build_step_up_challenge).map(|b| json!({ "$bytes": b64e(&b) })))),
            "stepUpChallengeB64u" => source(&args[0]).map(|s| same(want, with_src(&s, step_up_challenge_b64u).map(Value::String))),
            f @ ("buildApprovalChallenge" | "approvalChallengeForActn") => match (source(&args[0]), args[1].as_str()) {
                (Some(s), Some(rd)) => Some(same(
                    want,
                    if f == "buildApprovalChallenge" {
                        with_src(&s, |s| build_approval_challenge(s, rd)).map(|b| json!({ "$bytes": b64e(&b) }))
                    } else {
                        with_src(&s, |s| approval_challenge_for_actn(s, rd)).map(Value::String)
                    },
                )),
                _ => None,
            },
            "spcPaymentError" => args[2].as_str().map(|rp| same(want, spc_payment_error(&args[0], &args[1], rp).map(|o| o.map_or(Value::Null, Value::String)))),
            "verifyAssertion" => verify_case(&args).map(|got| {
                let reason = want["result"]["reason"].as_str().unwrap_or("");
                if runtime(reason) {
                    // the reason carries a TypeError text: the native verdict must refuse with the same prefix
                    let prefix = reason.split(':').next().unwrap();
                    match got["result"]["reason"].as_str() {
                        Some(g) if got["result"]["ok"] == json!(false) && g.starts_with(prefix) && got["regression"] == want["regression"] => Ok(()),
                        _ => Err(format!("want {want}, got {got}")),
                    }
                } else {
                    same(want, Ok(got))
                }
            }),
            f => Some(Err(format!("unknown fn {f}"))),
        };
        match r {
            None => skipped += 1,
            Some(r) => {
                ran += 1;
                if let Err(e) = r {
                    fails.push(format!("{name}: {e}"));
                }
            }
        }
    }
    assert!(skipped * 10 < ran, "too many skipped: {skipped} of {ran}");
    assert!(fails.is_empty(), "{} of {ran} cases differ:\n{}", fails.len(), fails.join("\n"));
}
