//! `strict_parse_bytes`, `is_canonical_compact_jws`, `decode_canonical_json_segment`.
use atlas_pca::jose::{decode_canonical_json_segment, is_canonical_compact_jws, DEFAULT_MAX_JWS_BYTES};
use atlas_pca::serde_json::json;
use atlas_pca::strict_parse_bytes;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};

#[test]
fn bytes_are_strict_parsed() {
    assert_eq!(strict_parse_bytes(br#"{"a":[1,2]}"#).unwrap(), json!({"a": [1, 2]}));
    assert!(strict_parse_bytes(&[0xff, 0xfe]).unwrap_err().contains("not valid UTF-8"));
    assert!(strict_parse_bytes(br#"{"a":1,"a":2}"#).is_err(), "duplicate keys");
    assert!(strict_parse_bytes(&[0xef, 0xbb, 0xbf, b'{', b'}']).is_err(), "a BOM");
}

#[test]
fn canonical_compact_jws_has_one_spelling() {
    let tok = format!("{}.{}.{}", B.encode(br#"{"alg":"none"}"#), B.encode(br#"{"a":1}"#), B.encode([1u8, 2, 3]));
    let ok = |t: &str| is_canonical_compact_jws(&json!(t), 3, DEFAULT_MAX_JWS_BYTES, true);
    assert!(ok(&tok));
    assert!(!ok(&format!("{tok}=")) && !ok(&format!("{tok}\n")) && !ok(&format!(" {tok}")));
    assert!(!ok("a.b"), "segment count");
    assert!(!is_canonical_compact_jws(&json!(5), 3, DEFAULT_MAX_JWS_BYTES, true));
    let dup = format!("{}.{}.{}", B.encode(br#"{"alg":"a","alg":"b"}"#), B.encode(br#"{}"#), B.encode([1u8]));
    assert!(!ok(&dup), "duplicate header key");
    // trailing-bit alias of the signature segment: AQI (1,2) vs AQJ decode alike in a lenient decoder
    assert!(!ok(&format!("{}.{}.AQJ", B.encode(br#"{"a":1}"#), B.encode(br#"{}"#))));
}

#[test]
fn a_json_segment_decodes_any_type() {
    assert_eq!(decode_canonical_json_segment(&B.encode(br#"["salt","k",1]"#)).unwrap(), json!(["salt", "k", 1]));
    assert!(decode_canonical_json_segment("AQJ").is_err());
    assert!(decode_canonical_json_segment(&B.encode(br#"[1,]"#)).is_err());
}
