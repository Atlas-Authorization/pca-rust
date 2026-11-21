//! base differential oracle for undo windows (pure layer): tests/data/base-undo.json.gz, written by the TypeScript reference
//! (tools/pca-audit/oracles-base/undo-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file). Secrets are the
//! base64url of a 32-byte Ed25519 seed; `now` that is not a JSON number is passed as NaN (the reference refuses it the same way).
use super::*;
use crate::k042_support::{base_run_seeded, Base};

fn num(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

fn val(r: Option<String>) -> Base {
    r.map_or(Base::Throw(None), |s| Base::Val(json!(s)))
}

fn key(v: &Value) -> Option<KeyPair> {
    KeyPair::from_seed_b64u(v.as_str()?).ok()
}

fn signed(r: Result<Value, String>) -> Base {
    r.map_or(Base::Throw(None), Base::Val)
}

#[test]
fn base_undo_matches_the_reference() {
    base_run_seeded("undo", 5000, |_case, f, a| match f {
        "compensationDigest" => val(compensation_digest(&a[0])),
        "signUndoToken" => key(&a[1]).map_or(Base::Skip("a KeyPair cannot hold a malformed key (typed port)"), |k| signed(sign_undo_token(&a[0], &k))),
        "undoTokenCheck" => Base::Val(json!(undo_token_check(&a[0], a[1].as_str().unwrap_or(""), &a[2], num(&a[3])))),
        "encodeUndoToken" => signed(encode_undo_token(&a[0]).map(Value::String)),
        "undoTokenDigest" => val(undo_token_digest(&a[0])),
        "decodeUndoToken" => Base::Val(a[0].as_str().and_then(decode_undo_token).unwrap_or(Value::Null)),
        "signUndoReceipt" => key(&a[1]).map_or(Base::Throw(None), |k| signed(sign_undo_receipt(&a[0], &k))),
        "undoReceiptDigest" => val(undo_receipt_digest(&a[0])),
        // a non-string pin is no key: nothing verifies against it
        "verifyUndoReceipt" => Base::Val(json!(a[1].as_str().is_some_and(|s| verify_undo_receipt(&a[0], s)))),
        "undoReceiptChainError" => Base::Val(match a[1].as_str() {
            Some(s) => json!(undo_receipt_chain_error(&a[0], s)),
            None => return Base::Skip("non-string signer pin"),
        }),
        "undoTransition" => Base::Val(match undo_transition(&a[0], &a[1], num(&a[2])) {
            UndoTransition::Applied { record, event, note } => json!({"outcome": "applied", "record": record, "receipt": {"event": event, "note": note}}),
            UndoTransition::Replayed => json!({"outcome": "replayed", "record": a[0]}),
            UndoTransition::Refused { code, reason } => json!({"outcome": "refused", "code": code, "reason": reason}),
        }),
        "resolveUndoWindow" => {
            let p = &a[1];
            let pol = UndoWindowPolicy { min_ms: p.get("minMs").and_then(Value::as_f64), max_ms: p.get("maxMs").and_then(Value::as_f64), default_ms: p.get("defaultMs").and_then(Value::as_f64) };
            Base::Val(json!(resolve_undo_window(a[0].as_f64(), &pol)))
        }
        _ => Base::Skip("fn not in this module"),
    });
}
