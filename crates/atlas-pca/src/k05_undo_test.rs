//! k05 differential oracle for undo windows (pure layer): tests/data/k05-undo.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/undo-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file). Secrets are the
//! base64url of a 32-byte Ed25519 seed; `now` that is not a JSON number is passed as NaN (the reference refuses it the same way).
use super::*;
use crate::k042_support::{k05_run, K05};

fn num(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn val(r: Option<String>) -> K05 {
    r.map_or(K05::Throw(None), |s| K05::Val(json!(s)))
}

fn key(v: &Value) -> Option<KeyPair> {
    KeyPair::from_seed_b64u(v.as_str()?).ok()
}

fn signed(r: Result<Value, String>) -> K05 {
    r.map_or(K05::Throw(None), K05::Val)
}

#[test]
fn k05_undo_matches_the_reference() {
    k05_run("undo", 5000, |_case, f, a| match f {
        "compensationDigest" => val(compensation_digest(&a[0])),
        "signUndoToken" => key(&a[1]).map_or(K05::Skip("a KeyPair cannot hold a malformed key (typed port)"), |k| signed(sign_undo_token(&a[0], &k))),
        "undoTokenCheck" => K05::Val(json!(undo_token_check(&a[0], a[1].as_str().unwrap_or(""), &a[2], num(&a[3])))),
        "encodeUndoToken" => signed(encode_undo_token(&a[0]).map(Value::String)),
        "undoTokenDigest" => val(undo_token_digest(&a[0])),
        "decodeUndoToken" => K05::Val(a[0].as_str().and_then(decode_undo_token).unwrap_or(Value::Null)),
        "signUndoReceipt" => key(&a[1]).map_or(K05::Throw(None), |k| signed(sign_undo_receipt(&a[0], &k))),
        "undoReceiptDigest" => val(undo_receipt_digest(&a[0])),
        // a non-string pin is no key: nothing verifies against it
        "verifyUndoReceipt" => K05::Val(json!(a[1].as_str().is_some_and(|s| verify_undo_receipt(&a[0], s)))),
        "undoReceiptChainError" => K05::Val(match a[1].as_str() {
            Some(s) => json!(undo_receipt_chain_error(&a[0], s)),
            None => return K05::Skip("non-string signer pin"),
        }),
        "undoTransition" => K05::Val(match undo_transition(&a[0], &a[1], num(&a[2])) {
            UndoTransition::Applied { record, event, note } => json!({"outcome": "applied", "record": record, "receipt": {"event": event, "note": note}}),
            UndoTransition::Replayed => json!({"outcome": "replayed", "record": a[0]}),
            UndoTransition::Refused { code, reason } => json!({"outcome": "refused", "code": code, "reason": reason}),
        }),
        "resolveUndoWindow" => {
            let p = &a[1];
            let pol = UndoWindowPolicy { min_ms: p.get("minMs").and_then(Value::as_f64), max_ms: p.get("maxMs").and_then(Value::as_f64), default_ms: p.get("defaultMs").and_then(Value::as_f64) };
            K05::Val(json!(resolve_undo_window(a[0].as_f64(), &pol)))
        }
        _ => K05::Skip("fn not in this module"),
    });
}
