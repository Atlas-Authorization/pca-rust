//! O4: the LENIENT canonical form (content addressing, Merkle leaves) prints every JSON number as ECMAScript `Number::toString` of the
//! double `JSON.parse` yields (packages/pca/src/hash.ts), so the digests match the reference for exponents and beyond 2^53.
use atlas_pca::canonicalize;
use atlas_pca::serde_json::{self, Value};

fn lenient(text: &str) -> String {
    canonicalize(&serde_json::from_str::<Value>(text).unwrap())
}

#[test]
fn numbers_print_as_javascript_prints_them() {
    for (text, want) in [
        ("0", "0"),
        ("-0", "0"),
        ("-0.0", "0"),
        ("1", "1"),
        ("-1", "-1"),
        ("0.1", "0.1"),
        ("1.5", "1.5"),
        ("100", "100"),
        ("1e2", "100"),
        ("123456789012345678", "123456789012345680"),
        ("9007199254740991", "9007199254740991"),
        ("9007199254740993", "9007199254740992"),
        ("-9223372036854775808", "-9223372036854776000"),
        ("18446744073709551615", "18446744073709552000"),
        ("100000000000000000000", "100000000000000000000"),
        ("1e21", "1e+21"),
        ("1.5e21", "1.5e+21"),
        ("-1e21", "-1e+21"),
        ("123456789e30", "1.23456789e+38"),
        ("0.000001", "0.000001"),
        ("1e-6", "0.000001"),
        ("1e-7", "1e-7"),
        ("1.5e-7", "1.5e-7"),
        ("5e-324", "5e-324"),
        ("1.7976931348623157e308", "1.7976931348623157e+308"),
    ] {
        assert_eq!(lenient(text), want, "{text}");
    }
}

#[test]
fn numbers_inside_documents_use_the_same_form() {
    assert_eq!(lenient(r#"{"b":[1e21,1e-7,18446744073709551615],"a":-0}"#), r#"{"a":0,"b":[1e+21,1e-7,18446744073709552000]}"#);
}
