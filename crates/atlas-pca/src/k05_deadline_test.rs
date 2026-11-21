//! k05 deadline kill tests (BRIEF "Timeouts are not kills"): every loop the 0.5 mutation run saw time out, driven with
//! ORDINARY input under `k042_support::within`, so a mutant that stops the loop advancing fails here in 2 s. Private helpers
//! of other modules are driven from their own test modules (agent, intent_map, dcap, ocsp, nvidia, predicates, caveat_lang).
use crate::k042_support::within;
use serde_json::json;

#[test]
fn merkle_split_and_path_shape_terminate() {
    // split: `k *= 2` must grow k; path_shape: `while n > 1` must stop at a single leaf
    assert_eq!(within("split(5)", || crate::split(5)), 4);
    assert_eq!(within("split(3)", || crate::split(3)), 2);
    assert_eq!(within("path_shape(0, 1)", || crate::path_shape(0, 1)), Vec::<u8>::new());
    assert_eq!(within("path_shape(2, 3)", || crate::path_shape(2, 3)), b"L".to_vec());
    assert_eq!(within("path_shape(0, 3)", || crate::path_shape(0, 3)), b"RR".to_vec());
}

#[test]
fn the_strict_json_parser_terminates() {
    // whitespace, a string with an escape, multi-digit integers and a fraction
    let v = within("strict_parse", || crate::strict_parse(" { \"a\\\"b\" :\t[ 12 , 3.25 ]\r\n} ").ok());
    assert_eq!(v.and_then(|v| v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())), Some(vec!["a\"b".to_string()]));
}

#[test]
fn the_rim_xml_parser_terminates() {
    // prolog PI, comment, DOCTYPE with an internal subset, attributes in both quotes, nested elements, text and a reference
    let xml = "<?xml version=\"1.0\"?>\n<!-- c -->\n<!DOCTYPE r [<!ENTITY e \"x\">]>\n<r a=\"1\" b='2'>\n  <c d=\"3\">t&amp;u</c><e/>tail</r>\n";
    // the profile refuses the PI / comment / DOCTYPE (a recorded violation), but the parser must still get through them
    let _ = within("parse_xml with a prolog", move || crate::attest::rim::parse_xml(xml).is_ok());
    let plain = "<r a=\"1\" b='2'>\n  <c d=\"3\">t&amp;u</c><e/>tail</r>";
    let _ = within("parse_xml", move || crate::attest::rim::parse_xml(plain).is_ok());
}

#[test]
fn small_attestation_parsers_terminate() {
    assert_eq!(within("parse_iso_ms", || crate::attest::util::parse_iso_ms("2024-01-02T03:04:05.678Z")), Some(1_704_164_645_678));
    let pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n";
    assert_eq!(within("pem_blocks", move || crate::attest::x509::pem_blocks(pem).len()), 2);
}

#[test]
fn occurs_as_token_tries_every_occurrence_and_terminates() {
    // the first occurrence is inside a word, so the scan must move on (`from = i + 1 char`) and find the token later
    assert!(within("occurs_as_token xa a", || crate::arg_provenance::occurs_as_token("xa a", "a")));
    assert!(within("occurs_as_token abab ab", || crate::arg_provenance::occurs_as_token("abab ab", "ab")));
    assert!(!within("occurs_as_token xax", || crate::arg_provenance::occurs_as_token("xaxa", "a")));
}

#[test]
fn rfc9162_inclusion_fold_terminates() {
    // index 2 of 3: the right edge (fnn == sn, even), where the fold shifts fnn down to 0
    let h = vec![0u8; 32];
    let p = vec![vec![1u8; 32]];
    let ok = within("verify_rfc9162_inclusion", move || crate::provenance_gate::verify_rfc9162_inclusion(&h, 2, 3, &p, &[2u8; 32]));
    assert!(!ok);
}

#[test]
fn ledger_consistency_fold_terminates() {
    let b = |x: u8| crate::b64_encode(&[x; 32]);
    // oldSize 1 (fnn = 0 from the start) and oldSize 3 -> 4 (the right-edge branch that shifts fnn down to 0)
    let (o1, n1, p1) = (json!(b(1)), json!(b(2)), json!({"oldSize": 1, "newSize": 2, "path": [b(3)]}));
    assert!(!within("ledger 1 -> 2", move || crate::ledger::verify_ledger_consistency(&o1, &n1, &p1)));
    let (o3, n3, p3) = (json!(b(1)), json!(b(2)), json!({"oldSize": 3, "newSize": 4, "path": [b(3), b(4), b(5)]}));
    assert!(!within("ledger 3 -> 4", move || crate::ledger::verify_ledger_consistency(&o3, &n3, &p3)));
}
