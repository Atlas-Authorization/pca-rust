//! 0.5 hardening (H5, H7, H9, H10, H11, H12, H20): configuration typing is refused at construction instead of silently dropping a gate, and
//! attestation JSON / RIM XML input is bounded before parsing. Mirrors packages/pca/src/mutation-kill-hardening-config.test.ts (the
//! reference): same inputs, same texts, every branch and boundary pinned.
use super::dcap::{collateral_unreadable, verify_signed_json};
use super::factory::verifier_from_config;
use super::jws::parse_jws;
use super::k05_cert_support::spki_p256;
use super::rim::verify_nvidia_rim;
use super::util::MAX_ATTEST_JSON_BYTES;
use super::x509::parse_spki;
use serde_json::{json, Value};

const M48: &str = "aa7c9da55c1386e5b1653b125978beda7b3f95a85aeb0f9ddbbdb783ce056a28c9d021da239c34a58c3a657654270eef";
const H32: &str = "fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e";

fn err(vendor: &str, cfg: &Value) -> Option<String> {
    verifier_from_config(vendor, cfg).err()
}

fn bad_lists() -> Vec<Value> {
    vec![json!("aa"), json!(5), json!({"0": "aa"}), json!(true), json!(["aa", 1]), json!([null]), json!([["aa"]]), json!([{}])]
}

fn ok_lists() -> Vec<Option<Value>> {
    vec![None, Some(json!(null)), Some(json!([])), Some(json!(["aa"])), Some(json!(["aa", "bb"]))]
}

// ---- H10: optional allowlists must be arrays of strings at construction

fn check_lists(vendor: &str, ctor: &str, base: &Value, keys: &[&str]) {
    for key in keys {
        let with = |v: &Option<Value>| {
            let mut c = base.clone();
            if let Some(v) = v {
                c["policy"][*key] = v.clone();
            }
            c
        };
        for bad in bad_lists() {
            assert_eq!(err(vendor, &with(&Some(bad.clone()))), Some(format!("{ctor}: policy.{key} must be an array of strings")), "{ctor} {key} {bad}");
        }
        for ok in ok_lists() {
            assert_eq!(err(vendor, &with(&ok)), None, "{ctor} {key} {ok:?}");
        }
    }
}

#[test]
fn optional_allowlists_must_be_arrays_of_strings() {
    check_lists("amd-sev-snp", "createAmdSnpVerifier", &json!({"family": "genoa", "binding": "report-data", "policy": {"measurements": [M48]}}), &["hostData", "chipIds"]);
    check_lists("intel-tdx-dcap", "createIntelDcapVerifier", &json!({"binding": "report-data", "policy": {"mrtds": [M48]}}), &["fmspcs", "rtmrs"]);
    check_lists(
        "azure-maa",
        "createAzureMaaVerifier",
        &json!({"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": ["aa"]}, "policy": {"tdxMrtds": [M48]}}),
        &["sevSnpHostData", "tdxRtmrs", "tdxAllowedTcbStatuses"],
    );
}

#[test]
fn a_string_allowlist_can_no_longer_act_as_a_substring_match_for_tdx_tcb_statuses() {
    let cfg = json!({"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": ["aa"]}, "policy": {"tdxMrtds": [M48], "tdxAllowedTcbStatuses": "UpToDateAndMore"}});
    assert_eq!(err("azure-maa", &cfg).as_deref(), Some("createAzureMaaVerifier: policy.tdxAllowedTcbStatuses must be an array of strings"));
}

// ---- H11: policy.collateral must be an object

#[test]
fn policy_collateral_must_be_an_object() {
    let mk = |c: Value| err("intel-tdx-dcap", &json!({"binding": "report-data", "policy": {"mrtds": [M48], "collateral": c}}));
    for bad in [json!("x"), json!(""), json!(5), json!(0), json!(true), json!(false), json!([]), json!([1])] {
        assert_eq!(mk(bad.clone()).as_deref(), Some("createIntelDcapVerifier: policy.collateral must be an object"), "{bad}");
    }
    for ok in [json!(null), json!({}), json!({"minTcbEvaluationDataNumber": 7}), json!({"acceptStatuses": ["UpToDate"]})] {
        assert_eq!(mk(ok.clone()), None, "{ok}");
    }
    // absent
    assert_eq!(err("intel-tdx-dcap", &json!({"binding": "report-data", "policy": {"mrtds": [M48]}})), None);
}

// ---- H20: a non-integer SVN floor is refused (already enforced; pinned)

#[test]
fn an_unreadable_svn_floor_is_refused_at_construction() {
    let mk = |f: Option<Value>| {
        let mut p = json!({"sevSnpMeasurements": [M48]});
        if let Some(f) = f {
            p["sevSnpMinTcb"] = json!({"snp": f});
        }
        err("azure-maa", &json!({"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": ["aa"]}, "policy": p}))
    };
    for bad in [json!([5]), json!("5"), json!(null), json!(-1), json!(1.5), json!({})] {
        assert_eq!(mk(Some(bad.clone())).as_deref(), Some("createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer"), "{bad}");
    }
    for ok in [Some(json!(0)), Some(json!(1)), Some(json!(27)), None] {
        assert_eq!(mk(ok.clone()), None, "{ok:?}");
    }
}

// ---- H9: NVIDIA configuration typing

fn nv(policy_extra: Value, collateral: Value) -> Value {
    let mut c = json!({"rootSpkiSha256": [H32], "policy": {"measurements": {"1": "aa"}}, "collateral": {"rimRootSpkiSha256": ["aa"]}});
    if let Value::Object(m) = policy_extra {
        for (k, v) in m {
            c["policy"][k] = v;
        }
    }
    if let Value::Object(m) = collateral {
        for (k, v) in m {
            c["collateral"][k] = v;
        }
    }
    c
}

#[test]
fn leaf_subject_includes_must_be_a_string() {
    for bad in [json!(5), json!(true), json!([]), json!(["GH100"]), json!({}), json!(0), json!(false)] {
        assert_eq!(err("nvidia-gpu-spdm", &nv(json!({"leafSubjectIncludes": bad.clone()}), json!({}))).as_deref(), Some("createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string"), "{bad}");
    }
    for ok in [json!(null), json!(""), json!("GH100")] {
        assert_eq!(err("nvidia-gpu-spdm", &nv(json!({"leafSubjectIncludes": ok.clone()}), json!({}))), None, "{ok}");
    }
}

#[test]
fn collateral_must_be_an_object_when_present() {
    for bad in [json!("x"), json!(5), json!(true), json!([]), json!(false)] {
        let mut c = nv(json!({}), json!({}));
        c["collateral"] = bad.clone();
        assert_eq!(err("nvidia-gpu-spdm", &c).as_deref(), Some("createNvidiaSpdmVerifier: collateral must be an object"), "{bad}");
    }
}

#[test]
fn firmware_must_be_an_object() {
    let fw = |v: Value| err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": v})));
    for ok in [json!(null), json!({})] {
        assert_eq!(fw(ok.clone()), None, "{ok}");
    }
    for bad in [json!("x"), json!(""), json!(5), json!(0), json!(true), json!(false), json!([]), json!(["a"])] {
        assert_eq!(fw(bad.clone()).as_deref(), Some("nvidiaCollateralHook: firmware must be an object"), "{bad}");
    }
}

#[test]
fn a_minimum_version_must_be_a_string_when_set() {
    for k in ["minDriverVersion", "minVbiosVersion"] {
        let fw = |v: Value| err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": {k: v}})));
        for (bad, shown) in [(json!(535), "535"), (json!(true), "true"), (json!({}), "[object Object]"), (json!([]), ""), (json!(["1"]), "1")] {
            assert_eq!(fw(bad.clone()), Some(format!("nvidiaCollateralHook: malformed {k} '{shown}'")), "{k} {bad}");
        }
        for ok in [json!(null), json!(""), json!(0), json!(false)] {
            assert_eq!(fw(ok.clone()), None, "{k} {ok}");
        }
        assert_eq!(fw(json!("1.x")), Some(format!("nvidiaCollateralHook: malformed {k} '1.x'")));
    }
    assert_eq!(err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": {"minDriverVersion": "535.1"}}))), None);
    assert_eq!(err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": {"minVbiosVersion": "96.00.9f"}}))), None);
}

#[test]
fn deny_lists_are_arrays_of_version_strings() {
    for k in ["denyDriverVersions", "denyVbiosVersions"] {
        let fw = |v: Value| err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": {k: v}})));
        for (bad, shown) in [(json!("535.1"), "535.1"), (json!(5), "5"), (json!({}), "[object Object]"), (json!(true), "true")] {
            assert_eq!(fw(bad.clone()), Some(format!("nvidiaCollateralHook: malformed {k} entry '{shown}'")), "{k} {bad}");
        }
        assert_eq!(fw(json!(["1.1", 5])), Some(format!("nvidiaCollateralHook: malformed {k} entry '5'")), "{k}");
        for ok in [json!(null), json!([])] {
            assert_eq!(fw(ok.clone()), None, "{k} {ok}");
        }
    }
    assert_eq!(err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": {"denyDriverVersions": ["535.1", "535.2"]}}))), None);
    assert_eq!(err("nvidia-gpu-spdm", &nv(json!({}), json!({"firmware": {"denyVbiosVersions": ["96.00.9f"]}}))), None);
}

#[test]
fn require_crl_issuers_lists_only_strings() {
    let r = |v: Value| err("nvidia-gpu-spdm", &nv(json!({}), json!({"requireCrlIssuers": v})));
    for bad in [json!("NVIDIA GH100"), json!(5), json!({}), json!([1]), json!(["a", null])] {
        assert_eq!(r(bad.clone()).as_deref(), Some("nvidiaCollateralHook: requireCrlIssuers must list only strings"), "{bad}");
    }
    for ok in [json!(null), json!([]), json!(["NVIDIA GH100"])] {
        assert_eq!(r(ok.clone()), None, "{ok}");
    }
}

// ---- H5: RIM XML nesting is refused before parsing

const NEST: &str = "RIM: verification error (fail closed): XML nesting is too deep";

fn rim(xml: &str) -> String {
    match verify_nvidia_rim(xml, &["aa".to_string()], 0.0) {
        Ok(_) => "OK".into(),
        Err(r) => r,
    }
}

fn nest(n: usize, inner: &str) -> String {
    format!("{}{}{}", "<a>".repeat(n), inner, "</a>".repeat(n))
}

#[test]
fn xml_nesting_past_64_is_refused_before_parsing() {
    assert_eq!(rim(&nest(65, "")), NEST);
    assert_ne!(rim(&nest(64, "")), NEST);
    assert_eq!(rim(&nest(1000, "")), NEST);
}

#[test]
fn a_huge_depth_is_refused_fast() {
    let t = std::time::Instant::now();
    assert_eq!(rim(&"<a>".repeat(1_000_000)), NEST);
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "{:?}", t.elapsed());
}

#[test]
fn closing_tags_unwind_the_depth() {
    assert_ne!(rim(&format!("<r>{}</r>", "<a></a>".repeat(5000))), NEST);
    assert_ne!(rim(&format!("{}{}", nest(64, ""), nest(64, ""))), NEST);
}

#[test]
fn self_closing_tags_comments_cdata_pis_and_doctype_never_count() {
    let d64 = |inner: &str| nest(64, inner);
    for x in [
        d64(&"<b/>".repeat(500)),
        d64(&"<b x=\"1\" />".repeat(500)),
        d64(&format!("<!-- {} -->", "<c>".repeat(200))),
        d64(&format!("<![CDATA[{}]]>", "<c>".repeat(200))),
        d64(&format!("<?pi {} ?>", "<c>".repeat(200))),
        format!("<!DOCTYPE a [ <!ENTITY e \"<c>\"> ]>{}", nest(64, "")),
    ] {
        assert_ne!(rim(&x), NEST, "{}", &x[..x.len().min(60)]);
    }
}

#[test]
fn a_quoted_gt_inside_an_attribute_does_not_end_the_tag_and_a_quoted_slash_is_not_a_self_close() {
    assert_eq!(rim(&format!("{}{}", "<a x=\">\">".repeat(65), "</a>".repeat(65))), NEST);
    assert_eq!(rim(&format!("{}{}", "<a x=\"/\">".repeat(65), "</a>".repeat(65))), NEST);
    assert_eq!(rim(&format!("{}{}", "<a x='>'>".repeat(65), "</a>".repeat(65))), NEST);
    assert_ne!(rim(&"<a x=\">\"/>".repeat(500)), NEST);
}

#[test]
fn an_unterminated_construct_or_tag_ends_the_scan_without_a_verdict() {
    for x in [format!("{}<!-- never closed", nest(10, "")), format!("{}<![CDATA[ never", nest(10, "")), format!("{}<?pi never", nest(10, "")), "<!DOCTYPE never".to_string(), "<a x=\"never>".to_string()] {
        assert_ne!(rim(&x), NEST, "{x}");
    }
}

// ---- H7: attestation JSON segments over 16 MiB are refused before parsing

fn b64u(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Exactly `n` bytes of valid JSON.
fn pad(n: usize) -> Vec<u8> {
    format!("{{\"a\":\"{}\"}}", "x".repeat(n - 8)).into_bytes()
}

#[test]
fn jws_json_segments_of_exactly_16_mib_parse_and_one_byte_more_is_refused() {
    let n = MAX_ATTEST_JSON_BYTES;
    assert_eq!(n, 16_777_216);
    let sig = b64u(&[1, 2, 3]);
    let hdr = b64u(b"{\"alg\":\"ES256\"}");
    for f in ["parseMaaJwt", "parseGcpCsJwt"] {
        let too = format!("{f}: malformed JSON segment: input too large");
        let p = parse_jws(&format!("{hdr}.{}.{sig}", b64u(&pad(n))), f);
        assert!(p.as_ref().err().is_none_or(|e| !e.contains("too large")), "{f}: {:?}", p.err());
        assert_eq!(parse_jws(&format!("{hdr}.{}.{sig}", b64u(&pad(n + 1))), f).err(), Some(too.clone()));
        let big_hdr = |len: usize| b64u(format!("{{\"alg\":\"ES256\",\"p\":\"{}\"}}", "x".repeat(len - 22)).as_bytes());
        let p = parse_jws(&format!("{}.{}.{sig}", big_hdr(n), b64u(b"{}")), f);
        assert!(p.as_ref().err().is_none_or(|e| !e.contains("too large")), "{f}: {:?}", p.err());
        assert_eq!(parse_jws(&format!("{}.{}.{sig}", big_hdr(n + 1), b64u(b"{}")), f).err(), Some(too));
    }
}

#[test]
fn an_oversize_payload_is_refused_before_a_malformed_header_is_parsed() {
    // the reference decodes both segments, size-checks both, and only then parses: so the size wins over a header that is not JSON
    let sig = b64u(&[1, 2, 3]);
    let got = parse_jws(&format!("{}.{}.{sig}", b64u(b"not json"), b64u(&pad(MAX_ATTEST_JSON_BYTES + 1))), "parseMaaJwt");
    assert_eq!(got.err().as_deref(), Some("parseMaaJwt: malformed JSON segment: input too large"));
}

#[test]
fn a_signed_intel_document_of_exactly_16_mib_is_parsed_and_one_more_is_refused_with_its_name() {
    let key = parse_spki(&spki_p256(1)).unwrap();
    let doc = |n: usize| {
        let (head, tail) = ("{\"tcbInfo\":{\"a\":\"", "\"},\"signature\":\"zz\"}");
        format!("{head}{}{tail}", "x".repeat(n - head.len() - tail.len()))
    };
    let n = MAX_ATTEST_JSON_BYTES;
    assert_eq!(verify_signed_json(&doc(n), "tcbInfo", &key).err().as_deref(), Some("tcbInfo signature missing or malformed"));
    assert_eq!(verify_signed_json(&doc(n + 1), "tcbInfo", &key).err().as_deref(), Some("tcbInfo: malformed JSON segment: input too large"));
    assert_eq!(verify_signed_json(&doc(n + 1), "qeIdentity", &key).err().as_deref(), Some("qeIdentity: malformed JSON segment: input too large"));
}

// ---- H12: evidence.collateral that is truthy but not an object is a failure, never "missing"

#[test]
fn unreadable_intel_collateral_is_not_missing() {
    for bad in [json!("x"), json!(5), json!(-1), json!(true), json!([]), json!([1]), json!(0.5)] {
        assert!(collateral_unreadable(Some(&bad)), "{bad}");
    }
    for ok in [json!(null), json!(false), json!(0), json!(""), json!({}), json!({"tcbInfoJson": "x"})] {
        assert!(!collateral_unreadable(Some(&ok)), "{ok}");
    }
    assert!(!collateral_unreadable(None));
}
