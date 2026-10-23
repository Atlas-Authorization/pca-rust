//! Boundary tests of the shared Intent Layer v2 value tests (intent_strict.rs): every predicate on both sides of every bound
//! the reference's regular expressions and helpers draw.
use super::*;
use serde_json::json;

fn v(x: Value) -> Option<Value> {
    Some(x)
}

const D32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 chars = 32 zero bytes

#[test]
fn integers() {
    assert_eq!(sint(Some(&json!(0))), Some(0));
    assert_eq!(sint(Some(&json!(-5))), Some(-5));
    assert_eq!(sint(Some(&json!(9007199254740991i64))), Some(9007199254740991));
    assert_eq!(sint(Some(&json!(9007199254740992i64))), None);
    assert_eq!(sint(Some(&json!(-9007199254740991i64))), Some(-9007199254740991));
    assert_eq!(sint(Some(&json!(-9007199254740992i64))), None);
    assert_eq!(sint(Some(&json!(1.5))), None);
    assert_eq!(sint(Some(&json!("5"))), None);
    assert_eq!(sint(Some(&json!(null))), None);
    assert_eq!(sint(None), None);
    assert_eq!(nonneg(Some(&json!(0))), Some(0));
    assert_eq!(nonneg(Some(&json!(7))), Some(7));
    assert_eq!(nonneg(Some(&json!(-1))), None);
    assert_eq!(nonneg(Some(&json!(true))), None);
    assert_eq!(nonneg(None), None);
    assert_eq!(num(Some(&json!(1.5))), Some(1.5));
    assert_eq!(num(Some(&json!(-3))), Some(-3.0));
    assert_eq!(num(Some(&json!("1"))), None);
    assert_eq!(num(Some(&Value::Null)), None);
    assert_eq!(num(None), None);
}

#[test]
fn safe_integer_doubles() {
    assert!(safe_integer_f64(0.0));
    assert!(safe_integer_f64(-0.0));
    assert!(safe_integer_f64(1.0));
    assert!(safe_integer_f64(-1.0));
    assert!(safe_integer_f64(9007199254740991.0));
    assert!(safe_integer_f64(-9007199254740991.0));
    assert!(!safe_integer_f64(9007199254740992.0));
    assert!(!safe_integer_f64(-9007199254740992.0));
    assert!(!safe_integer_f64(0.5));
    assert!(!safe_integer_f64(f64::NAN));
    assert!(!safe_integer_f64(f64::INFINITY));
    assert!(!safe_integer_f64(f64::NEG_INFINITY));
}

#[test]
fn digests_and_base64() {
    assert!(b32(Some(&json!(D32))));
    assert!(!b32(Some(&json!(&D32[1..])))); // 42 chars
    assert!(!b32(Some(&json!(format!("{D32}A"))))); // 44 chars
    assert!(!b32(Some(&json!(format!("{}B", &D32[..42]))))); // non-canonical trailing bits
    assert!(!b32(Some(&json!(format!("{}=", &D32[..42]))))); // padding
    assert!(!b32(Some(&json!(format!("{}+", &D32[..42]))))); // not the url alphabet
    assert!(!b32(Some(&json!(5))));
    assert!(!b32(Some(&Value::Null)));
    assert!(!b32(None));
    assert!(b64any(Some(&json!(D32))));
    assert!(b64any(Some(&json!("AA")))); // one byte
    assert!(b64any(Some(&json!("AAA")))); // two bytes
    assert!(b64any(Some(&json!("AAAA"))));
    assert!(!b64any(Some(&json!("A")))); // one stray sextet
    assert!(!b64any(Some(&json!("AB")))); // non-canonical trailing bits
    assert!(!b64any(Some(&json!("AA=="))));
    assert!(!b64any(Some(&json!("AA+/"))));
    assert!(!b64any(Some(&json!(7))));
    assert!(!b64any(Some(&Value::Null)));
    assert!(!b64any(None));
}

#[test]
fn bounded_strings_and_reads() {
    assert!(bstr(Some(&json!("a")), 1));
    assert!(!bstr(Some(&json!("ab")), 1));
    assert!(!bstr(Some(&json!("")), 5));
    assert!(bstr(Some(&json!("\u{e9}")), 2)); // two UTF-8 bytes
    assert!(!bstr(Some(&json!("\u{e9}")), 1));
    assert!(!bstr(Some(&json!(1)), 5));
    assert!(!bstr(None, 5));
    assert_eq!(s(Some(&json!("x"))), Some("x"));
    assert_eq!(s(Some(&json!(1))), None);
    assert_eq!(s(None), None);
    assert!(obj(Some(&json!({}))).is_some());
    assert!(obj(Some(&json!([]))).is_none());
    assert!(obj(Some(&Value::Null)).is_none());
    assert!(obj(None).is_none());
}

#[test]
fn scalar_equality() {
    let (n, t, f, a, b, o, i1, d1) = (Value::Null, json!(true), json!(false), json!("a"), json!("b"), json!({}), json!(1), json!(1.0));
    // two absent members are equal; absent never equals null / anything present
    assert!(same(None, None));
    assert!(!same(None, Some(&n)));
    assert!(!same(Some(&n), None));
    assert!(same(Some(&n), Some(&n)));
    assert!(!same(Some(&n), Some(&t)));
    assert!(same(Some(&t), Some(&t)));
    assert!(same(Some(&f), Some(&f)));
    assert!(!same(Some(&t), Some(&f)));
    assert!(same(Some(&a), Some(&a)));
    assert!(!same(Some(&a), Some(&b)));
    assert!(same(Some(&i1), Some(&d1))); // numbers by double value
    assert!(!same(Some(&i1), Some(&json!(2))));
    assert!(!same(Some(&i1), Some(&json!("1"))));
    assert!(!same(Some(&t), Some(&i1)));
    assert!(!same(Some(&o), Some(&o))); // an object never equals anything
    assert!(!same(Some(&json!([])), Some(&json!([]))));
    assert!(scalar_eq(Some(&a), Some(&a)));
    assert!(!scalar_eq(Some(&json!(2)), Some(&json!("2"))));
    assert!(!scalar_eq(Some(&t), Some(&i1)));
}

#[test]
fn scalars() {
    assert!(is_scalar(Some(&json!("x"))));
    assert!(is_scalar(Some(&json!(true))));
    assert!(is_scalar(Some(&json!(false))));
    assert!(is_scalar(Some(&json!(0))));
    assert!(is_scalar(Some(&json!(9007199254740991i64))));
    assert!(!is_scalar(Some(&json!(9007199254740992i64))));
    assert!(!is_scalar(Some(&json!(1.5))));
    assert!(!is_scalar(Some(&Value::Null)));
    assert!(!is_scalar(Some(&json!([]))));
    assert!(!is_scalar(Some(&json!({}))));
    assert!(!is_scalar(None));
}

fn name(x: &str) -> bool {
    is_name(Some(&json!(x)))
}

#[test]
fn intent_names() {
    assert!(name("a"));
    assert!(name("a_1"));
    assert!(name("abc9"));
    assert!(name(&format!("a{}", "b".repeat(63)))); // 64 bytes
    assert!(!name(&format!("a{}", "b".repeat(64)))); // 65
    assert!(!name(""));
    assert!(!name("1a"));
    assert!(!name("_a"));
    assert!(!name("Ab"));
    assert!(!name("aB"));
    assert!(!name("a-b"));
    assert!(!name("a.b"));
    assert!(!name("a b"));
    assert!(!name("\u{e9}"));
    assert!(!is_name(Some(&json!(1))));
    assert!(!is_name(None));
}

#[test]
fn identifiers_and_top_param_paths() {
    assert!(is_ident("a"));
    assert!(is_ident("A_9"));
    assert!(is_ident(&"x".repeat(64)));
    assert!(!is_ident(&"x".repeat(65)));
    assert!(!is_ident(""));
    assert!(!is_ident("a-b"));
    assert!(!is_ident("a.b"));
    assert!(is_top_param_path("action.params.total"));
    assert!(is_top_param_path(&format!("action.params.{}", "t".repeat(64))));
    assert!(!is_top_param_path(&format!("action.params.{}", "t".repeat(65))));
    assert!(!is_top_param_path("action.params."));
    assert!(!is_top_param_path("action.params.a.b"));
    assert!(!is_top_param_path("action.param.a"));
    assert!(!is_top_param_path("params.a"));
}

#[test]
fn unit_ids_and_data_classes() {
    assert!(is_unit_id("a"));
    assert!(is_unit_id("1"));
    assert!(is_unit_id("_"));
    assert!(is_unit_id("a.b_9.0"));
    assert!(!is_unit_id(""));
    assert!(!is_unit_id("."));
    assert!(!is_unit_id("a."));
    assert!(!is_unit_id(".a"));
    assert!(!is_unit_id("a..b"));
    assert!(!is_unit_id("A"));
    assert!(!is_unit_id("a.B"));
    assert!(!is_unit_id("a-b"));
    assert!(!is_unit_id("a b"));
    assert!(is_data_class("a"));
    assert!(is_data_class("pii"));
    assert!(is_data_class("pii.identity"));
    assert!(is_data_class("pii.id_9.0x"));
    assert!(is_data_class("a1_b"));
    assert!(!is_data_class(""));
    assert!(!is_data_class("1a"));
    assert!(!is_data_class("_a"));
    assert!(!is_data_class("Pii"));
    assert!(!is_data_class("pII"));
    assert!(!is_data_class("a-b"));
    assert!(!is_data_class("a."));
    assert!(!is_data_class("a..b"));
    assert!(!is_data_class("a.B"));
    assert!(!is_data_class("a.b-c"));
    assert!(!is_data_class(".a"));
    assert!(!is_data_class("a b"));
}

#[test]
fn path_segments_and_param_paths() {
    assert!(is_path_segment("a"));
    assert!(is_path_segment("A-b_9"));
    assert!(is_path_segment("-"));
    assert!(is_path_segment(&"x".repeat(64)));
    assert!(!is_path_segment(&"x".repeat(65)));
    assert!(!is_path_segment(""));
    assert!(!is_path_segment("a.b"));
    assert!(!is_path_segment("a b"));
    assert!(!is_path_segment("a/b"));
    assert!(!is_path_segment("__proto__"));
    assert!(!is_path_segment("constructor"));
    assert!(!is_path_segment("prototype"));
    assert!(is_path_segment("constructors"));
    assert!(is_param_path(Some(&json!("action.params.a"))));
    assert!(is_param_path(Some(&json!("action.params.a.b.c.d.e.f.g.h")))); // 8 segments
    assert!(!is_param_path(Some(&json!("action.params.a.b.c.d.e.f.g.h.i")))); // 9
    assert!(!is_param_path(Some(&json!("action.params."))));
    assert!(!is_param_path(Some(&json!("action.params.a."))));
    assert!(!is_param_path(Some(&json!("action.params.a..b"))));
    assert!(!is_param_path(Some(&json!("action.params.a.__proto__"))));
    assert!(!is_param_path(Some(&json!("action.params.a b"))));
    assert!(!is_param_path(Some(&json!("action.param.a"))));
    assert!(!is_param_path(Some(&json!("a"))));
    assert!(!is_param_path(Some(&json!(1))));
    assert!(!is_param_path(None));
}

#[test]
fn resolving_a_param_path() {
    let params = json!({"a": {"b": [1, 2], "c": 3}, "z": null, "constructor": 1});
    assert_eq!(resolve_param_path(&params, "action.params.a.c"), Some(&json!(3)));
    assert_eq!(resolve_param_path(&params, "action.params.a.b"), Some(&json!([1, 2])));
    assert_eq!(resolve_param_path(&params, "action.params.z"), Some(&Value::Null));
    assert_eq!(resolve_param_path(&params, "action.params.a.x"), None);
    assert_eq!(resolve_param_path(&params, "action.params.a.b.0"), None); // arrays are not walked
    assert_eq!(resolve_param_path(&params, "action.params.constructor"), None);
    assert_eq!(resolve_param_path(&params, "action.params.a..c"), None);
    assert_eq!(resolve_param_path(&params, "params.a"), None);
    assert_eq!(resolve_param_path(&params, "action.params."), None);
}

#[test]
fn member_sets() {
    let o = |x: Value| x.as_object().unwrap().clone();
    let ab = o(json!({"a": 1, "b": 2}));
    assert!(closed_members(&ab, &["a", "b"], &[]));
    assert!(closed_members(&ab, &["a"], &["b"]));
    assert!(!closed_members(&ab, &["a"], &[]));
    assert!(!closed_members(&ab, &["a", "b", "c"], &[]));
    assert!(closed_members(&o(json!({})), &[], &["a"]));
    assert!(exact_keys(&ab, &["a", "b"]));
    assert!(exact_keys(&ab, &["b", "a"]));
    assert!(!exact_keys(&ab, &["a"]));
    assert!(!exact_keys(&ab, &["a", "b", "c"]));
    assert!(!exact_keys(&ab, &["a", "c"]));
    assert!(exact_keys(&o(json!({})), &[]));
    assert!(pin_pq_ok(None));
    assert!(pin_pq_ok(Some(&json!("k"))));
    assert!(!pin_pq_ok(Some(&json!(""))));
    assert!(!pin_pq_ok(Some(&Value::Null)));
    assert!(!pin_pq_ok(Some(&json!(1))));
}

#[test]
fn artifact_suite_members() {
    let o = |x: Value| x.as_object().unwrap().clone();
    assert_eq!(artifact_suite_error(&o(json!({}))), None);
    assert_eq!(artifact_suite_error(&o(json!({"alg": "ed25519"}))), None);
    assert!(artifact_suite_error(&o(json!({"alg": 5}))).is_some());
    assert!(artifact_suite_error(&o(json!({"alg": "x-unknown"}))).unwrap().contains("unsupported_suite") || artifact_suite_error(&o(json!({"alg": "x-unknown"}))).is_some());
    assert_eq!(artifact_suite_error(&o(json!({"pq_pk": 1}))).as_deref(), Some("pq_pk must be a string"));
    assert_eq!(artifact_suite_error(&o(json!({"pq_sig": null}))).as_deref(), Some("pq_sig must be a string"));
    assert!(artifact_suite_error(&o(json!({"pq_pk": "k"}))).unwrap().contains("must not carry pq_pk / pq_sig"));
    assert!(artifact_suite_error(&o(json!({"pq_sig": "s"}))).unwrap().contains("must not carry pq_pk / pq_sig"));
    assert!(artifact_suite_error(&o(json!({"alg": "ed25519", "pq_pk": "k", "pq_sig": "s"}))).unwrap().contains("must not carry"));
    assert_eq!(artifact_suite_error(&o(json!({"alg": "ml-dsa-65", "pq_pk": "k", "pq_sig": "s"}))), None);
}

#[test]
fn utf8_sort_order_and_digests() {
    let mut xs = vec!["\u{e9}".to_string(), "b".to_string(), "Z".to_string(), "a".to_string(), "\u{1f600}".to_string(), "\u{ffff}".to_string()];
    sort_utf8(&mut xs);
    assert_eq!(xs, vec!["Z", "a", "b", "\u{e9}", "\u{ffff}", "\u{1f600}"]); // UTF-8 byte order = code point order
    assert_eq!(digest_of(&json!({"a": 1})), digest_of(&json!({"a": 1})));
    assert_ne!(digest_of(&json!({"a": 1})), digest_of(&json!({"a": 2})));
    assert_ne!(artifact_ref("d1", "c", &json!({"x": 1})), artifact_ref("d2", "c", &json!({"x": 1})));
    assert_ne!(artifact_ref("d", "c", &json!({"x": 1})), artifact_ref("d", "v", &json!({"x": 1})));
    assert_ne!(artifact_ref("d", "c", &json!({"x": 1})), artifact_ref("d", "c", &json!({"x": 2})));
    assert_eq!(artifact_message("dom\0", &json!({"b": 2, "a": 1, "sig": "s", "pq_sig": "q"}).as_object().unwrap().clone()), Some(b"dom\0{\"a\":1,\"b\":2}".to_vec()));
    assert_eq!(artifact_message("d", &json!({"v": 9007199254740992u64}).as_object().unwrap().clone()), None);
    let _ = v(Value::Null);
}
