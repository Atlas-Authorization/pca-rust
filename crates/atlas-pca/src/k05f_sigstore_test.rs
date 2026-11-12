//! RFC 3161 timestamp cap (packages/pca-attest-eat sigstore.ts MAX_RFC3161_TIMESTAMPS = 8): a bundle naming more is refused at
//! stage `tsa` before any CMS / chain / signature work; exactly 8 reaches the verification (and fails there on the bogus bytes).
use super::*;
use crate::k042_support::k05_cases;
use std::collections::BTreeMap;

fn roots() -> BTreeMap<String, PinnedRoots> {
    let mut m = BTreeMap::new();
    for c in k05_cases("sigstore") {
        if c["fn"] == "parseTrustedRoot" {
            if let (Some(id), Ok(r)) = (c["name"].as_str().and_then(|n| n.strip_prefix("parseTrustedRoot/")), parse_trusted_root(&c["args"][0])) {
                m.insert(id.to_string(), r);
            }
        }
    }
    m
}

fn with_timestamps(bundle: &Value, n: usize) -> Value {
    let mut b = bundle.clone();
    let list: Vec<Value> = (0..n).map(|_| json!({"signedTimestamp": "AAAA"})).collect();
    b["verificationMaterial"]["timestampVerificationData"] = json!({"rfc3161Timestamps": list});
    b
}

#[test]
fn more_than_eight_rfc3161_timestamps_are_refused_before_any_verification() {
    let roots = roots();
    // a bundle the reference accepts: every stage before `tsa` passes on it
    let case = k05_cases("sigstore")
        .find(|c| c["fn"] == "verifySigstoreBundleCore" && c["out"]["ok"] == true && c["args"][1]["$root"].as_str().is_some_and(|id| roots.contains_key(id)))
        .expect("an accepted verifySigstoreBundleCore case");
    let root = &roots[case["args"][1]["$root"].as_str().unwrap()];
    let bundle = &case["args"][0];

    let nine = verify_sigstore_bundle_core(&with_timestamps(bundle, 9), root).err().expect("9 timestamps are refused");
    assert_eq!((nine.code, nine.detail.as_str()), ("tsa", "too many RFC 3161 timestamps (9, at most 8)"));
    let many = verify_sigstore_bundle_core(&with_timestamps(bundle, 300), root).err().expect("300 timestamps are refused");
    assert_eq!(many.detail, "too many RFC 3161 timestamps (300, at most 8)");

    // exactly 8 is within the cap: the refusal is the bogus timestamp, not the cap
    let eight = verify_sigstore_bundle_core(&with_timestamps(bundle, 8), root).err().expect("8 bogus timestamps still fail");
    assert!(!eight.detail.starts_with("too many"), "{}", eight.detail);
    assert_eq!(MAX_RFC3161_TIMESTAMPS, 8);
}

// ---- the duplicate-extension scan is linear (a HashSet), in both extension parsers

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    match body.len() {
        n if n < 0x80 => v.push(n as u8),
        n if n < 0x100 => v.extend_from_slice(&[0x81, n as u8]),
        n if n < 0x10000 => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        n => v.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
    }
    v.extend_from_slice(body);
    v
}

/// Extension { OID 1.3.6.1.4.1.99999.<i>, OCTET STRING {} } (the arc `i` in base-128).
fn ext_n(i: u32) -> Vec<u8> {
    let mut arc = vec![(i & 0x7f) as u8];
    let mut rest = i >> 7;
    while rest > 0 {
        arc.push(0x80 | (rest & 0x7f) as u8);
        rest >>= 7;
    }
    arc.reverse();
    // 1.3 = 0x2b, 6 1 4 1, then 99999 = 0x86 0x8d 0x1f
    let mut oid = vec![0x2b, 6, 1, 4, 1, 0x86, 0x8d, 0x1f];
    oid.extend_from_slice(&arc);
    der(0x30, &[der(0x06, &oid), der(0x04, &[])].concat())
}

const MANY: u32 = 100_000;

#[test]
fn a_hundred_thousand_distinct_extensions_parse_fast_and_a_duplicate_is_still_refused() {
    let exts: Vec<Vec<u8>> = (0..MANY).map(ext_n).collect();
    let tbs = der(0x30, &der(0xa3, &der(0x30, &exts.concat())));
    let cert = der(0x30, &tbs);

    let t = std::time::Instant::now();
    assert_eq!(parse_cert(&cert).unwrap().exts.len(), MANY as usize);
    assert_eq!(crate::attest::der::parse_tbs_extensions(&tbs).unwrap().len(), MANY as usize);
    assert!(t.elapsed() < std::time::Duration::from_secs(20), "the scan must not be quadratic: {:?}", t.elapsed());

    // the duplicate is refused with the same text, at either end of the list
    let mut dup = exts;
    dup.push(ext_n(0));
    let tbs = der(0x30, &der(0xa3, &der(0x30, &dup.concat())));
    let refused = parse_cert(&der(0x30, &tbs)).err().expect("duplicate refused");
    assert!(refused.starts_with("duplicate extension 1.3.6.1.4.1.99999.0"), "{refused}");
    let refused = crate::attest::der::parse_tbs_extensions(&tbs).err().expect("duplicate refused");
    assert_eq!(refused, "duplicate extension 1.3.6.1.4.1.99999.0");
}
