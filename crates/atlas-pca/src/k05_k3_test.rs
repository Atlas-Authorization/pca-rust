//! k05 kill tests pinned to packages/pca-grants/src/{bundle,list-authorized,grant-resource}.ts: each clause alone, every other member
//! valid and the signature good where the check runs before it.
use super::*;
use crate::agent::KeyPair;

fn key() -> KeyPair {
    KeyPair::from_seed(&[1u8; 32])
}

fn sig_of(k: &KeyPair, domain: &str, body: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(k.sign(&crate::fresh_at::domain_bytes(domain, body).unwrap()))
}

fn patched(mut base: Value, patch: &Value) -> Value {
    for (k, x) in patch.as_object().unwrap() {
        base[k.as_str()] = x.clone();
    }
    base
}

#[test]
fn is_str_is_one_to_max_utf16_units() {
    assert!(is_str(Some(&json!("ab")), 2));
    assert!(is_str(Some(&json!("\u{1F600}")), 2));
    for bad in [json!(""), json!("abc"), json!("\u{1F600}a"), json!(5)] {
        assert!(!is_str(Some(&bad), 2), "{bad}");
    }
}

#[test]
fn truthy_is_javascript_truthiness() {
    for yes in [json!("a"), json!(1), json!(-1.5), json!(true), json!([]), json!({})] {
        assert!(truthy(Some(&yes)), "{yes}");
    }
    for no in [json!(""), json!(0), json!(0.0), json!(-0.0), json!(false), json!(null)] {
        assert!(!truthy(Some(&no)), "{no}");
    }
    assert!(!truthy(None));
}

#[test]
fn versions_compare_numerically_and_a_non_number_is_greater() {
    for (a, b, want) in [("1.2", "1.10", -1), ("1.10", "1.2", 1), ("1.0", "1", 0), ("1", "1.0.0", 0), ("2", "1.9", 1), ("1", "1.1", -1), ("x", "1", 1), ("1", "x", 1)] {
        assert_eq!(compare_version(a, b), want, "{a} {b}");
    }
}

fn bundle(patch: Value) -> Value {
    patched(json!({"v": 1, "kind": "pca-policy-bundle", "revision": 1, "issued_at": 0, "grants": [], "template_digests": [], "min_verifier_version": "1.0.0"}), &patch)
}

#[test]
fn bundle_shape_refuses_each_clause_alone() {
    let many = |n: usize| json!(vec!["g"; n]);
    assert_eq!(bundle_shape_error(&bundle(json!({}))), None);
    assert_eq!(bundle_shape_error(&bundle(json!({"grants": many(4096), "template_digests": many(4096)}))), None);
    assert_eq!(bundle_shape_error(&bundle(json!({"revision": 2, "prev": "p"}))), None);
    for ok in [json!(["a"]), json!(["a", "b"]), json!(vec!["x".repeat(128)]), json!((0..16).map(|i| format!("s{i}")).collect::<Vec<_>>())] {
        assert_eq!(bundle_shape_error(&bundle(json!({ "shadow": ok }))), None, "{ok}");
    }
    let cases = [
        (json!({"v": 2}), "not a policy bundle"),
        (json!({"kind": "x"}), "not a policy bundle"),
        (json!({"revision": 0}), "bad revision or time"),
        (json!({"issued_at": -1}), "bad revision or time"),
        (json!({"grants": many(4097)}), "bad grants"),
        (json!({"grants": [""]}), "bad grants"),
        (json!({"grants": ["g".repeat(129)]}), "bad grants"),
        (json!({"template_digests": many(4097)}), "bad template_digests"),
        (json!({"template_digests": [""]}), "bad template_digests"),
        (json!({"shadow": null}), "bad shadow"),
        (json!({"shadow": []}), "bad shadow"),
        (json!({"shadow": "a"}), "bad shadow"),
        (json!({"shadow": [""]}), "bad shadow"),
        (json!({"shadow": ["x".repeat(129)]}), "bad shadow"),
        (json!({"shadow": ["a", "a"]}), "bad shadow"),
        (json!({"shadow": (0..17).map(|i| format!("s{i}")).collect::<Vec<_>>()}), "bad shadow"),
    ];
    for (patch, want) in cases {
        assert_eq!(bundle_shape_error(&bundle(patch.clone())).as_deref(), Some(want), "{patch}");
    }
}

#[test]
fn signature_list_and_threshold_are_bounded_first() {
    let with_sigs = |n: usize| bundle(json!({ "sigs": vec![json!({"signer": "x", "sig": "y"}); n] }));
    let code = |b: &Value, threshold: i64| verify_bundle(b, &["k"], threshold, "1.0.0", None);
    let malformed = json!({"ok": false, "code": "malformed", "reason": "bad sigs or threshold"});
    for (n, t) in [(0, 0), (0, -1), (0, 1i64 << 53), (65, 1)] {
        assert_eq!(code(&with_sigs(n), t), malformed, "{n} {t}");
    }
    assert_eq!(code(&with_sigs(64), 1)["code"], json!("below_threshold"));
    assert_eq!(code(&with_sigs(0), (1i64 << 53) - 1)["code"], json!("below_threshold"));
}

fn receipt(k: &KeyPair, patch: Value) -> Value {
    let body = patched(json!({"v": 1, "signer": k.public, "subject": "s", "resource_type": "t", "count": 0, "issued_at": 0}), &patch);
    let sig = sig_of(k, LIST_RECEIPT_DOMAIN, &body);
    patched(body, &json!({ "sig": sig }))
}

#[test]
fn list_receipt_refuses_each_clause_under_a_valid_signature() {
    let k = key();
    assert!(verify_list_receipt(&receipt(&k, json!({"subject": "s".repeat(512), "resource_type": "t".repeat(512)})), &k.public, None));
    for patch in [
        json!({"v": 2}),
        json!({"signer": "other"}),
        json!({"subject": ""}),
        json!({"subject": "s".repeat(513)}),
        json!({"resource_type": ""}),
        json!({"resource_type": "t".repeat(513)}),
        json!({"count": -1}),
        json!({"issued_at": -1}),
    ] {
        assert!(!verify_list_receipt(&receipt(&k, patch.clone()), &k.public, None), "{patch}");
    }
}

fn cursor_token(k: &KeyPair, c: &Value) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_string(c).unwrap()), sig_of(k, LIST_CURSOR_DOMAIN, c))
}

#[test]
fn list_cursor_refuses_each_clause_under_a_valid_signature() {
    let k = key();
    let base = json!({"v": 1, "signer": k.public, "bind": "b", "skip": 3});
    let check = |tok: String| verify_list_cursor(&json!(tok), &k.public, None);
    let malformed = json!({"ok": false, "reason": "malformed"});
    let good = cursor_token(&k, &base);
    assert_eq!(check(good.clone()), json!({"ok": true, "skip": 3}));
    assert_eq!(check(cursor_token(&k, &patched(base.clone(), &json!({"inner": "i"})))), json!({"ok": true, "skip": 3, "inner": "i"}));
    assert_eq!(check(format!("{good}.x")), malformed, "a third part");
    let payload = good.split('.').next().unwrap();
    assert_eq!(check(format!("{payload}.")), malformed, "an empty signature");
    assert_eq!(check(payload.to_string()), malformed, "no signature");
    let mut no_bind = base.clone();
    no_bind.as_object_mut().unwrap().remove("bind");
    assert_eq!(check(cursor_token(&k, &no_bind)), malformed, "no bind");
    for patch in [json!({"v": 2}), json!({"bind": 5}), json!({"skip": -1}), json!({"skip": "3"}), json!({"inner": 5})] {
        assert_eq!(check(cursor_token(&k, &patched(base.clone(), &patch))), malformed, "{patch}");
    }
}

#[test]
fn authority_lists_and_limits_are_bounded() {
    let auth = |patch: Value| Authority::from_json(&patched(json!({"verbs": [], "resources": []}), &patch));
    for ok in [json!({"verbs": vec!["v"; 256]}), json!({"resources": vec!["r"; 1024]}), json!({"verbs": ["v".repeat(128)], "resources": ["r".repeat(512)]}), json!({"limits": {"x": 0}})] {
        assert!(auth(ok.clone()).is_some(), "{ok}");
    }
    for bad in [json!({"verbs": vec!["v"; 257]}), json!({"resources": vec!["r"; 1025]}), json!({"verbs": [""]}), json!({"verbs": ["v".repeat(129)]}), json!({"resources": ["r".repeat(513)]}), json!({"limits": {"x": -1}})] {
        assert!(auth(bad.clone()).is_none(), "{bad}");
    }
}

#[test]
fn authority_json_writes_an_integral_amount_as_an_integer() {
    let of = |f: f64| {
        let a = Authority { limits: BTreeMap::from([("x".to_string(), f)]), ..Authority::default() };
        a.to_json()["limits"]["x"].clone()
    };
    assert!(of(5.0).is_i64());
    assert_eq!(of(5.0), json!(5));
    assert!(of(1.5).is_f64());
    assert!(of(8_999_999_999_999_999.0).is_i64());
    assert!(of(9.0e15).is_f64(), "serde_json keeps the double; strict canonical output is the same text");
    assert!(of(-5.0).is_i64());
    let e = Authority { expires_at: Some(5.0), ..Authority::default() };
    assert!(e.to_json()["expires_at"].is_i64());
}

#[test]
fn resources_cover_exactly_or_by_a_star_prefix() {
    let list = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert!(res_covers("a", "a"));
    assert!(!res_covers("a", "b"));
    assert!(res_covers("a*", "ab"));
    assert!(!res_covers("a*", "b"));
    for (small, big, want) in [
        (&["abc"][..], &["a*"][..], true),
        (&["abc"][..], &["abc"][..], true),
        (&["abc"][..], &["abd"][..], false),
        (&["a*"][..], &["a*"][..], true),
        (&["ab*"][..], &["a*"][..], true),
        (&["a*"][..], &["ab*"][..], false),
        (&["a*"][..], &["abc"][..], false),
        (&["a*"][..], &["a"][..], false),
    ] {
        assert_eq!(res_subset(&list(small), &list(big)), want, "{small:?} {big:?}");
    }
}

#[test]
fn an_amendment_request_that_is_not_an_object_is_a_bad_request() {
    for req in [json!("narrow"), json!(["narrow"]), json!({"action": "other"})] {
        assert_eq!(verify_amendment(&json!({"status": "active"}), &req, true), json!({"ok": false, "code": "bad_request"}), "{req}");
    }
}

#[test]
fn only_a_lowered_amount_needs_an_adjustable_need() {
    let k = key();
    let approve = |amount: i64, adjustable: Option<bool>| {
        let mut want = json!({"verb": "v", "resource": "r", "limits": {"x": 5}});
        if let Some(a) = adjustable {
            want["adjustable"] = json!(a);
        }
        let nr = json!({"id": "n", "grant_id": "g", "needs": [want], "status": "pending"});
        let g = json!({"rev": 1, "principal": k.public, "authority": {"verbs": [], "resources": []}});
        let approved = json!([{"verb": "v", "resource": "r", "limits": {"x": amount}}]);
        let sig = json!(sig_of(&k, NEED_APPROVE_DOMAIN, &json!({"need": "n", "grant": "g", "rev": 1, "approved": approved})));
        verify_need_approval(&nr, &g, &approved, Some(&sig), true)
    };
    assert_eq!(approve(5, None)["ok"], json!(true));
    assert_eq!(approve(4, None)["code"], json!("need_not_adjustable"));
    assert_eq!(approve(4, Some(false))["code"], json!("need_not_adjustable"));
    assert_eq!(approve(4, Some(true))["ok"], json!(true));
    assert_eq!(approve(6, Some(true))["code"], json!("need_not_lowered_only"));
}
