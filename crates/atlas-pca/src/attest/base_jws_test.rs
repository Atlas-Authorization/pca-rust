//! Kill tests for the JWS reader's texts (every `Unexpected token` row was read from node's `JSON.parse`) and the vendor names.

use super::{js_json_error, parse_jws};
use crate::attest::factory::Vendor;
use crate::attest::strict_chain_tests::es256_token;
use serde_json::{json, Value};

fn error_of(text: &str) -> String {
    js_json_error(text, &serde_json::from_str::<Value>(text).unwrap_err())
}

#[test]
fn the_context_window_of_an_unexpected_token_is_v8s() {
    let rows: [(usize, usize, &str); 16] = [
        (5, 20, r#"Unexpected token 'x', "     xyyyyyyyyyyyyyy" is not valid JSON"#),
        (19, 20, r#"Unexpected token 'x', "                   x" is not valid JSON"#),
        (0, 21, r#"Unexpected token 'x', "xyyyyyyyyy"... is not valid JSON"#),
        (9, 21, r#"Unexpected token 'x', "         xyyyyyyyyy"... is not valid JSON"#),
        (10, 21, r#"Unexpected token 'x', ..."          xyyyyyyyyy"... is not valid JSON"#),
        (11, 21, r#"Unexpected token 'x', ..."          xyyyyyyyyy" is not valid JSON"#),
        (20, 21, r#"Unexpected token 'x', ..."          x" is not valid JSON"#),
        (5, 30, r#"Unexpected token 'x', "     xyyyyyyyyy"... is not valid JSON"#),
        (9, 30, r#"Unexpected token 'x', "         xyyyyyyyyy"... is not valid JSON"#),
        (10, 30, r#"Unexpected token 'x', ..."          xyyyyyyyyy"... is not valid JSON"#),
        (15, 30, r#"Unexpected token 'x', ..."          xyyyyyyyyy"... is not valid JSON"#),
        (19, 30, r#"Unexpected token 'x', ..."          xyyyyyyyyy"... is not valid JSON"#),
        (20, 30, r#"Unexpected token 'x', ..."          xyyyyyyyyy" is not valid JSON"#),
        (25, 30, r#"Unexpected token 'x', ..."          xyyyy" is not valid JSON"#),
        (29, 30, r#"Unexpected token 'x', ..."          x" is not valid JSON"#),
        (3, 40, r#"Unexpected token 'x', "   xyyyyyyyyy"... is not valid JSON"#),
    ];
    for (at, n, want) in rows {
        let text = format!("{}x{}", " ".repeat(at), "y".repeat(n - at - 1));
        assert_eq!(error_of(&text), want, "token at {at} of {n}");
    }
}

#[test]
fn input_that_stops_early_is_the_end_of_input() {
    for text in ["", "[", "[1,", "{\"a\":", "tru", "nul"] {
        assert_eq!(error_of(text), "Unexpected end of JSON input", "{text}");
    }
}

#[test]
fn an_empty_alg_is_no_alg() {
    let parse = |header: Value| parse_jws(&es256_token(1, &header, &json!({})), "f").map(|j| j.alg);
    assert_eq!(parse(json!({ "alg": "" })), Err("f: header has no alg".to_string()));
    assert_eq!(parse(json!({})), Err("f: header has no alg".to_string()));
    assert_eq!(parse(json!({ "alg": "ES256" })), Ok("ES256".to_string()));
}

#[test]
fn vendor_names_round_trip() {
    for (vendor, name) in [
        (Vendor::AmdSevSnp, "amd-sev-snp"),
        (Vendor::IntelTdxDcap, "intel-tdx-dcap"),
        (Vendor::AzureMaa, "azure-maa"),
        (Vendor::GcpConfidentialSpace, "gcp-confidential-space"),
        (Vendor::NvidiaGpuSpdm, "nvidia-gpu-spdm"),
    ] {
        assert_eq!(vendor.name(), name);
        assert_eq!(Vendor::from_name(name), Some(vendor));
    }
}

fn token_of(header: &str, payload: &str) -> String {
    use base64::Engine;
    let b = |t: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(t.as_bytes());
    format!("{}.{}.c2ln", b(header), b(payload))
}

#[test]
fn a_duplicate_member_in_a_segment_is_invalid_json_and_other_number_spellings_parse() {
    let ok_header = r#"{"alg":"ES256","kid":"k1"}"#;
    assert!(parse_jws(&token_of(ok_header, r#"{"a":1,"b":2}"#), "parseMaaJwt").is_ok());
    let invalid = |h: &str, p: &str| parse_jws(&token_of(h, p), "parseMaaJwt").err();
    let want = Some("parseMaaJwt: malformed JSON segment: invalid JSON".to_string());
    assert_eq!(invalid(ok_header, r#"{"a":1,"a":2}"#), want, "a duplicate payload member");
    assert_eq!(invalid(r#"{"alg":"ES256","alg":"none"}"#, r#"{"a":1}"#), want, "a duplicate header member");
    // numbers stay as written: neither is a refusal of the segment
    assert!(parse_jws(&token_of(ok_header, r#"{"a":1e3,"b":1.0,"c":8.0}"#), "parseMaaJwt").is_ok());
    assert_eq!(invalid("not json", r#"{"a":1}"#), want, "a header that is not JSON");
    assert_eq!(invalid(ok_header, r#"{"a":"#), want, "a truncated payload");
}
