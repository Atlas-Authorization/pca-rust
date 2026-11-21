//! base differential oracle for the canonical approval render (K7): tests/data/base-approval.json.gz, written by the TypeScript
//! reference (tools/pca-audit/oracles-base/approval-oracle.mts; every native replays the same file). No def in the file carries a
//! signed confirmation, so every render is unreviewed (`confirmed = false`). `minorToDecimal` takes typed integers here: a case
//! whose args are not JSON integers is skipped (the reference refuses all of them); -0 is 0.
use super::*;
use crate::k042_support::{base_b64, base_run_seeded, Base};

fn coded<T>(r: Result<T, ApprovalError>, f: impl Fn(T) -> Value) -> Base {
    match r {
        Ok(v) => Base::Val(f(v)),
        Err(e) => Base::Throw(Some(e.code)),
    }
}

fn plain(r: Result<String, String>) -> Base {
    r.map_or(Base::Throw(None), |s| Base::Val(Value::String(s)))
}

/// A typed integer argument (-0 counts as 0); None for anything else.
fn int(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| (v.as_f64() == Some(0.0)).then_some(0))
}

#[test]
fn base_approval_matches_the_reference() {
    base_run_seeded("approval", 4400, |_, f, a| match f {
        "approvalRenderShapeError" => Base::Val(json!(approval_render_shape_error(&a[0]))),
        "approvalRenderDigest" => plain(approval_render_digest(&a[0])),
        "approvalChallengeB64u" => match (a[0].as_str(), a[1].as_str()) {
            (Some(x), Some(y)) => plain(approval_challenge(x, y)),
            _ => Base::Throw(None),
        },
        "bindingWords" => a[0].as_str().map_or(Base::Throw(None), |d| plain(binding_words(d))),
        "renderApproval" => coded(render_approval(&a[0], &a[1], false), |v| v),
        "psd2Linking" => coded(psd2_linking(&a[0]), |v| v),
        "minorToDecimal" => match (int(&a[0]), int(&a[1])) {
            (Some(m), Some(e)) => coded(minor_to_decimal(m, e), Value::String),
            _ => Base::Skip("args are not JSON integers (typed port)"),
        },
        "approvalBatch" => match a[0].as_array() {
            // the reference's challenge is the raw bytes: compare as {$bytes}
            Some(items) => coded(approval_batch(items), |mut v| {
                let raw = crate::decode_b64u_strict(v["challenge"].as_str().unwrap_or(""), None).unwrap_or_default();
                v["challenge"] = base_b64(&raw);
                v
            }),
            None => Base::Throw(None),
        },
        "validateDef" => Base::Val(json!(crate::actions::validate_def(&a[0]))),
        "spcExpectation" | "cibaApprovalDetails" => Base::Skip("SPC / CIBA views are not in the Rust SDK"),
        _ => Base::Skip("fn not in this module"),
    });
}

#[test]
fn batch_total_stops_at_the_safe_integer_range() {
    let item = |minor: i64, ad: &str| {
        // the corpus's "approvalBatch/one" item with its amount replaced
        let render = serde_json::json!({"v": 1, "kind": "pca-approval-render", "verb": "acme.pay", "def_digest": "NG0q4MT2WjnViFLG06gRIdbscJXf-PoVdeU5SOZk5Hc", "unreviewed": false, "fields": [
            {"id": "amount", "class": "money.amount", "value": minor, "unit": {"kind": "money", "ccy": "EUR", "exp": 2}},
            {"id": "payee", "class": "party.payee", "value": "A"}]});
        serde_json::json!({"action_digest": ad, "render": render})
    };
    let over = "the batch total exceeds the safe integer range";
    let e = approval_batch(&[item(MAX_SAFE - 1, "GCpVUX1GcrrLQVWUBqUYYzLcQL6YEoxx2l7xIq_XRwE"), item(2, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]).unwrap_err();
    assert_eq!((e.code.as_str(), e.message.as_str()), ("psd2_unlinkable", over));
    // exactly the limit is in range
    assert!(approval_batch(&[item(MAX_SAFE - 1, "GCpVUX1GcrrLQVWUBqUYYzLcQL6YEoxx2l7xIq_XRwE"), item(1, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]).err().map(|e| e.message).as_deref() != Some(over), "exactly the limit is in range");
}
