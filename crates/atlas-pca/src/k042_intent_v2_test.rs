//! Unit tests of the ECMAScript `String(...)` helpers of intent_v2.rs (`action_str`, `js_value_string`, `js_number_string`):
//! every branch, against the values JavaScript prints.
use super::*;
use serde_json::json;

fn num(t: &str) -> Value {
    serde_json::from_str(t).expect("json number")
}

#[test]
fn js_value_string_scalars() {
    assert_eq!(js_value_string(&Value::Null), "null");
    assert_eq!(js_value_string(&json!(true)), "true");
    assert_eq!(js_value_string(&json!(false)), "false");
    assert_eq!(js_value_string(&json!("")), "");
    assert_eq!(js_value_string(&json!("a b\u{e9}")), "a b\u{e9}");
    assert_eq!(js_value_string(&json!({})), "[object Object]");
    assert_eq!(js_value_string(&json!({"a": 1})), "[object Object]");
}

#[test]
fn js_value_string_arrays_join_with_commas() {
    assert_eq!(js_value_string(&json!([])), "");
    assert_eq!(js_value_string(&json!([1])), "1");
    assert_eq!(js_value_string(&json!([1, 2, 3])), "1,2,3");
    // null (and undefined) elements are empty
    assert_eq!(js_value_string(&json!([null])), "");
    assert_eq!(js_value_string(&json!([null, null])), ",");
    assert_eq!(js_value_string(&json!([1, null, 2])), "1,,2");
    assert_eq!(js_value_string(&json!([null, "a"])), ",a");
    // nested arrays flatten through String(), objects print as [object Object], booleans and strings as themselves
    assert_eq!(js_value_string(&json!([[1, 2], [3]])), "1,2,3");
    assert_eq!(js_value_string(&json!([[], 1])), ",1");
    assert_eq!(js_value_string(&json!([[null], "x"])), ",x");
    assert_eq!(js_value_string(&json!([{}, true, "s", 1.5])), "[object Object],true,s,1.5");
}

#[test]
fn js_value_string_integers() {
    assert_eq!(js_value_string(&json!(0)), "0");
    assert_eq!(js_value_string(&json!(7)), "7");
    assert_eq!(js_value_string(&json!(-7)), "-7");
    assert_eq!(js_value_string(&num("9007199254740991")), "9007199254740991");
    assert_eq!(js_value_string(&num("-9007199254740991")), "-9007199254740991");
    // past 2^53 a JSON integer is the nearest double, as JSON.parse has it
    assert_eq!(js_value_string(&num("9007199254740993")), "9007199254740992");
    assert_eq!(js_value_string(&num("18446744073709551615")), "18446744073709552000");
    assert_eq!(js_value_string(&num("-9223372036854775808")), "-9223372036854776000");
    assert_eq!(js_value_string(&num("123456789012345678901")), "123456789012345680000");
}

#[test]
fn js_value_string_fractions_and_exponents() {
    assert_eq!(js_value_string(&num("1.5")), "1.5");
    assert_eq!(js_value_string(&num("-1.5")), "-1.5");
    assert_eq!(js_value_string(&num("1.0")), "1");
    assert_eq!(js_value_string(&num("-0.0")), "0");
    assert_eq!(js_value_string(&num("0.0")), "0");
    assert_eq!(js_value_string(&num("0.1")), "0.1");
    assert_eq!(js_value_string(&num("123.456")), "123.456");
    assert_eq!(js_value_string(&num("0.000001")), "0.000001");
    assert_eq!(js_value_string(&num("0.0000012")), "0.0000012");
    // below 1e-6 JavaScript switches to an exponent
    assert_eq!(js_value_string(&num("0.0000001")), "1e-7");
    assert_eq!(js_value_string(&num("1.5e-7")), "1.5e-7");
    assert_eq!(js_value_string(&num("-1.5e-7")), "-1.5e-7");
    assert_eq!(js_value_string(&num("5e-324")), "5e-324");
    // up to 21 integer digits JavaScript is positional, from 1e21 it is an exponent
    assert_eq!(js_value_string(&num("1e20")), "100000000000000000000");
    assert_eq!(js_value_string(&num("1.5e20")), "150000000000000000000");
    assert_eq!(js_value_string(&num("1e21")), "1e+21");
    assert_eq!(js_value_string(&num("1.5e21")), "1.5e+21");
    assert_eq!(js_value_string(&num("-1e21")), "-1e+21");
    assert_eq!(js_value_string(&num("1.7976931348623157e308")), "1.7976931348623157e+308");
    assert_eq!(js_value_string(&num("12345.6789e3")), "12345678.9");
    assert_eq!(js_value_string(&num("2.5e-5")), "0.000025");
}

#[test]
fn js_number_string_special_values() {
    assert_eq!(js_number_string(f64::NAN), "NaN");
    assert_eq!(js_number_string(f64::INFINITY), "Infinity");
    assert_eq!(js_number_string(f64::NEG_INFINITY), "-Infinity");
    assert_eq!(js_number_string(-0.0), "0");
    assert_eq!(js_number_string(0.0), "0");
    assert_eq!(js_number_string(1.0), "1");
    assert_eq!(js_number_string(-1.0), "-1");
    assert_eq!(js_number_string(10.0), "10");
    assert_eq!(js_number_string(100.0), "100");
    assert_eq!(js_number_string(0.5), "0.5");
    assert_eq!(js_number_string(1e-6), "0.000001");
    assert_eq!(js_number_string(1e-7), "1e-7");
    assert_eq!(js_number_string(1e21), "1e+21");
    assert_eq!(js_number_string(999999999999999900000.0), "999999999999999900000");
}

#[test]
fn action_str_reads_the_action_member_like_string_of_optional_chaining() {
    let p = |v: Value| v.as_object().unwrap().clone();
    // action absent / null / not an object: undefined (JavaScript's `p.action?.verb`)
    assert_eq!(action_str(&p(json!({})), "verb"), "undefined");
    assert_eq!(action_str(&p(json!({"action": null})), "verb"), "undefined");
    assert_eq!(action_str(&p(json!({"action": "verb"})), "verb"), "undefined");
    assert_eq!(action_str(&p(json!({"action": ["verb"]})), "verb"), "undefined");
    assert_eq!(action_str(&p(json!({"action": 5})), "verb"), "undefined");
    assert_eq!(action_str(&p(json!({"action": true})), "verb"), "undefined");
    // the member absent
    assert_eq!(action_str(&p(json!({"action": {}})), "verb"), "undefined");
    assert_eq!(action_str(&p(json!({"action": {"resource": "r"}})), "verb"), "undefined");
    // the member present: String(value)
    assert_eq!(action_str(&p(json!({"action": {"verb": "air.book"}})), "verb"), "air.book");
    assert_eq!(action_str(&p(json!({"action": {"verb": "v", "resource": "r"}})), "resource"), "r");
    assert_eq!(action_str(&p(json!({"action": {"verb": null}})), "verb"), "null");
    assert_eq!(action_str(&p(json!({"action": {"verb": 5}})), "verb"), "5");
    assert_eq!(action_str(&p(json!({"action": {"verb": true}})), "verb"), "true");
    assert_eq!(action_str(&p(json!({"action": {"verb": ["a", null, 1]}})), "verb"), "a,,1");
    assert_eq!(action_str(&p(json!({"action": {"verb": {"x": 1}}})), "verb"), "[object Object]");
    assert_eq!(action_str(&p(json!({"action": {"verb": ""}})), "verb"), "");
    assert_eq!(action_str(&p(json!({"action": {"verb": 1.5e-7}})), "verb"), "1.5e-7");
}

#[test]
fn context_from_text() {
    let c = IntentV2Context::from_json_text("{\"params\": {\"a\": 1}}").unwrap();
    assert_eq!(c.as_json(), &json!({"params": {"a": 1}}));
    assert_ne!(c, IntentV2Context::default());
    assert_eq!(IntentV2Context::from_json_text("{}").unwrap().as_json(), &json!({}));
    assert!(IntentV2Context::from_json_text("[]").unwrap_err().contains("not a JSON object"));
    assert!(IntentV2Context::from_json_text("null").unwrap_err().contains("not a JSON object"));
    assert!(IntentV2Context::from_json_text("5").unwrap_err().contains("not a JSON object"));
    assert!(IntentV2Context::from_json_text("{").unwrap_err().starts_with("intent_v2 context: "));
}
