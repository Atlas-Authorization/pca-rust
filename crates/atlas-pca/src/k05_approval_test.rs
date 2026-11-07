//! k05 differential oracle for the canonical approval render (K7): tests/data/k05-approval.json.gz, written by the TypeScript
//! reference (tools/pca-audit/k05-oracles/approval-oracle.mts; every native replays the same file). No def in the file carries a
//! signed confirmation, so every render is unreviewed (`confirmed = false`). `minorToDecimal` takes typed integers here: a case
//! whose args are not JSON integers is skipped (the reference refuses all of them); -0 is 0.
use super::*;
use crate::k042_support::{k05_b64, k05_run, K05};

fn coded<T>(r: Result<T, ApprovalError>, f: impl Fn(T) -> Value) -> K05 {
    match r {
        Ok(v) => K05::Val(f(v)),
        Err(e) => K05::Throw(Some(e.code)),
    }
}

fn plain(r: Result<String, String>) -> K05 {
    r.map_or(K05::Throw(None), |s| K05::Val(Value::String(s)))
}

/// A typed integer argument (-0 counts as 0); None for anything else.
fn int(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| (v.as_f64() == Some(0.0)).then_some(0))
}

#[test]
fn k05_approval_matches_the_reference() {
    k05_run("approval", 4400, |_, f, a| match f {
        "approvalRenderShapeError" => K05::Val(json!(approval_render_shape_error(&a[0]))),
        "approvalRenderDigest" => plain(approval_render_digest(&a[0])),
        "approvalChallengeB64u" => match (a[0].as_str(), a[1].as_str()) {
            (Some(x), Some(y)) => plain(approval_challenge(x, y)),
            _ => K05::Throw(None),
        },
        "bindingWords" => a[0].as_str().map_or(K05::Throw(None), |d| plain(binding_words(d))),
        "renderApproval" => coded(render_approval(&a[0], &a[1], false), |v| v),
        "psd2Linking" => coded(psd2_linking(&a[0]), |v| v),
        "minorToDecimal" => match (int(&a[0]), int(&a[1])) {
            (Some(m), Some(e)) => coded(minor_to_decimal(m, e), Value::String),
            _ => K05::Skip("args are not JSON integers (typed port)"),
        },
        "approvalBatch" => match a[0].as_array() {
            // the reference's challenge is the raw bytes: compare as {$bytes}
            Some(items) => coded(approval_batch(items), |mut v| {
                let raw = crate::decode_b64u_strict(v["challenge"].as_str().unwrap_or(""), None).unwrap_or_default();
                v["challenge"] = k05_b64(&raw);
                v
            }),
            None => K05::Throw(None),
        },
        "validateDef" => K05::Val(json!(crate::actions::validate_def(&a[0]))),
        "spcExpectation" | "cibaApprovalDetails" => K05::Skip("SPC / CIBA views are not in the Rust SDK"),
        _ => K05::Skip("fn not in this module"),
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
