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
