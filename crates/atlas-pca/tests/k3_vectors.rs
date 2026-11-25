//! Shared operational-plane vectors: packages/pca/conformance/k3-vectors.json (`primitives.<kind>[] = {name, input, expect}`).
//! A missing file or table fails, it never skips.
use atlas_pca::fresh_at::{check_fresh_at, fresh_at_digest, verify_fresh_at, FreshAtState};
use atlas_pca::k3::*;
use atlas_pca::serde_json::{json, Value};

fn table(doc: &Value, kind: &str) -> Vec<Value> {
    let t = doc["primitives"][kind]
        .as_array()
        .unwrap_or_else(|| panic!("k3-vectors.json has no table {kind}"))
        .clone();
    assert!(!t.is_empty(), "{kind}: empty table");
    t
}

/// Run `f` over every entry of `kind` and compare with `expect` exactly (key order is irrelevant).
fn replay(doc: &Value, kind: &str, f: impl Fn(&Value) -> Value) {
    let mut bad = Vec::new();
    for e in table(doc, kind) {
        let got = f(&e["input"]);
        if got != e["expect"] {
            bad.push(format!("{}: got {got}, want {}", e["name"], e["expect"]));
        }
    }
    assert!(
        bad.is_empty(),
        "{kind}: {} failed:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn digest(d: Option<String>) -> Value {
    json!({ "digest": d })
}

#[test]
fn k3_primitives() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/k3-vectors.json"
    );
    let doc: Value = atlas_pca::serde_json::from_str(
        &std::fs::read_to_string(path).expect("read k3-vectors.json"),
    )
    .expect("parse k3-vectors.json");
    assert_eq!(doc["format"].as_i64(), Some(1));

    replay(
        &doc,
        "fresh_at_verify",
        |i| json!({"valid": verify_fresh_at(&i["token"], s(&i["signer"]))}),
    );
    replay(&doc, "fresh_at_digest", |i| {
        digest(fresh_at_digest(&i["token"]))
    });
    replay(&doc, "fresh_at_check", |i| {
        let o = &i["options"];
        let local = FreshAtState::from_json(&i["local"]).expect("local state");
        check_fresh_at(
            &i["token"],
            &local,
            s(&o["signer"]),
            s(&o["scope"]),
            o["now"].as_i64().unwrap(),
            o["maxTokenAgeMs"].as_i64(),
        )
        .to_json()
    });

    replay(&doc, "bundle_digest", |i| {
        digest(bundle_digest(&i["bundle"]))
    });
    replay(&doc, "bundle_verify", |i| {
        let o = &i["options"];
        let signers: Vec<&str> = o["signers"].as_array().unwrap().iter().map(s).collect();
        let last = o
            .get("last")
            .map(|l| (l["revision"].as_i64().unwrap(), s(&l["digest"])));
        verify_bundle(
            &i["bundle"],
            &signers,
            o["threshold"].as_i64().unwrap_or(0),
            s(&o["verifierVersion"]),
            last,
        )
    });

    replay(
        &doc,
        "log_commit",
        |i| json!({"commit": record_commit(&i["record"])}),
    );
    replay(
        &doc,
        "log_head_verify",
        |i| json!({"valid": verify_log_head(&i["head"], s(&i["signer"]))}),
    );
    replay(
        &doc,
        "log_inclusion",
        |i| json!({"valid": verify_record_inclusion(&i["record"], &i["proof"], &i["head"], s(&i["signer"]))}),
    );
    replay(&doc, "log_batch_verify", |i| {
        verify_batch(
            &i["batch"],
            i["state"]["next"].as_i64().unwrap(),
            s(&i["state"]["lastCommit"]),
            s(&i["signer"]),
        )
    });

    replay(&doc, "list_objects_digest", |i| {
        digest(objects_digest(&i["objects"]))
    });
    replay(
        &doc,
        "list_receipt_verify",
        |i| json!({"valid": verify_list_receipt(&i["receipt"], s(&i["signer"]), i.get("objects"))}),
    );
    replay(&doc, "list_bind", |i| digest(list_bind(&i["bind"])));
    replay(&doc, "list_cursor_verify", |i| {
        verify_list_cursor(&i["cursor"], s(&i["signer"]), i.get("bind"))
    });

    replay(&doc, "authority_digest", |i| {
        digest(authority_digest(&i["authority"]))
    });
    replay(
        &doc,
        "authority_compare",
        |i| json!({"order": compare_authority(&i["old"], &i["new"])}),
    );
    replay(&doc, "amend_verify", |i| {
        verify_amendment(
            &i["grant"],
            &i["request"],
            i["step_up_ok"].as_bool().unwrap_or(false),
        )
    });
    replay(&doc, "revoke_verify", |i| {
        verify_revoke_signature(&i["root"], &i["scope"], i.get("sig"))
    });
    replay(&doc, "need_approve_verify", |i| {
        verify_need_approval(
            &i["need_request"],
            &i["grant"],
            &i["approved"],
            i.get("sig"),
            i["step_up_ok"].as_bool().unwrap_or(false),
        )
    });
}

/// Every function is total: junk in, the failure value out, never a panic.
#[test]
fn k3_is_total_on_junk() {
    for junk in [
        json!(null),
        json!(7),
        json!("x"),
        json!([]),
        json!({}),
        json!({"v": 1, "sig": 5}),
    ] {
        assert!(!verify_fresh_at(&junk, "k"));
        assert!(!verify_log_head(&junk, "k"));
        assert!(!verify_list_receipt(&junk, "k", Some(&junk)));
        assert!(!verify_record_inclusion(&junk, &junk, &junk, "k"));
        assert_eq!(
            verify_bundle(&junk, &["k"], 1, "1.0.0", None)["ok"],
            json!(false)
        );
        assert_eq!(verify_batch(&junk, 0, "", "k")["ok"], json!(false));
        assert_eq!(
            verify_list_cursor(&junk, "k", Some(&junk))["ok"],
            json!(false)
        );
        assert_eq!(verify_amendment(&junk, &junk, true)["ok"], json!(false));
        assert_eq!(
            verify_revoke_signature(&junk, &junk, Some(&junk))["ok"],
            json!(false)
        );
        assert_eq!(
            verify_need_approval(&junk, &junk, &junk, Some(&junk), true)["ok"],
            json!(false)
        );
        assert_eq!(compare_authority(&junk, &junk), "incomparable");
    }
}
