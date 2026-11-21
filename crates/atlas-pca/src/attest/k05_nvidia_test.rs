//! NVIDIA SPDM parsing, the device chain, the RIM ids and comparison, CRL coverage, firmware versions and the chip name,
//! checked clause by clause. Limits and reasons follow attest-nvidia-spdm.ts and attest-nvidia-rim.ts.

use super::*;
use crate::attest::dcap::k05_dcap_test::signed_crl;
use crate::attest::rim::Golden;
use crate::attest::strict_chain_tests::{chain as chain_of, good_ca, good_leaf, mint, pem, spki, Curve, NOW};
use std::collections::BTreeMap;

const PRE: &str = "parseNvidiaSpdmEvidence";

#[test]
fn little_endian_fields_read_every_byte_and_a_missing_one_is_zero() {
    assert_eq!(u16le(&[1, 2, 3], 1), 0x0302);
    assert_eq!(u16le(&[1], 0), 1);
    assert_eq!(u24le(&[1, 2, 3, 4], 1), 0x04_0302);
    assert_eq!(u24le(&[1, 2], 0), 0x0201);
}

// ---- the transcript

fn transcript(rec: &[u8], num_blocks: u8, opaque: &[u8]) -> Vec<u8> {
    let mut b = vec![0x11, 0xe0, 0, 0];
    b.extend_from_slice(&[7; 32]);
    b.push(0);
    b.extend_from_slice(&[0x11, 0x60, 0, 0, num_blocks]);
    b.extend_from_slice(&(rec.len() as u32).to_le_bytes()[..3]);
    b.extend_from_slice(rec);
    b.extend_from_slice(&[8; 32]);
    b.extend_from_slice(&(opaque.len() as u16).to_le_bytes());
    b.extend_from_slice(opaque);
    b.extend_from_slice(&[9; 96]);
    b
}

/// A measurement block: index, spec, size, then type, vsize and `rest`.
fn block(index: u8, size: u16, vsize: u16, rest: &[u8]) -> Vec<u8> {
    let mut b = vec![index, 1];
    b.extend_from_slice(&size.to_le_bytes());
    b.push(1);
    b.extend_from_slice(&vsize.to_le_bytes());
    b.extend_from_slice(rest);
    b
}

fn reason(bytes: &[u8]) -> Option<String> {
    parse_spdm(bytes).err()
}

fn at(what: &str) -> Option<String> {
    Some(format!("{PRE}: {what}"))
}

#[test]
fn the_transcript_floor_is_175_bytes() {
    let mut short = vec![0u8; 174];
    short[1] = 0xe0;
    assert_eq!(reason(&short), at("transcript too short (174)"));

    let minimal = transcript(&[], 0, &[]);
    assert_eq!(minimal.len(), 175);
    let s = parse_spdm(&minimal).ok().unwrap();
    assert_eq!((s.request_version, s.response_version), (0x11, 0x11));
    assert_eq!(s.request_nonce, [7; 32]);
    assert!(s.measurements.is_empty() && s.opaque.is_empty());
    assert_eq!(s.signature, [9; 96]);
    assert_eq!(s.signed, minimal[..79]);
}

#[test]
fn the_record_length_must_leave_room_for_nonce_opaque_length_and_signature() {
    let mut over = transcript(&[], 0, &[]);
    over[37 + 5] = 1;
    assert_eq!(reason(&over), at("measurement record length overruns transcript"));
    assert_eq!(reason(&transcript(&[0, 0, 0], 0, &[])), at("truncated measurement block header"));
}

#[test]
fn measurement_block_table() {
    const RECORD: &str = "measurement block overruns record";
    const DMTF: &str = "DMTF value overruns measurement block";
    // size 3 is the smallest block (type + vsize), size 2 is too small even though it fits the record
    let s = parse_spdm(&transcript(&block(1, 3, 0, &[]), 1, &[])).ok().unwrap();
    assert_eq!(s.measurements, [(1, vec![])]);
    assert_eq!(reason(&transcript(&[1, 1, 2, 0, 1, 0], 1, &[])), at(RECORD));
    // the block's size covers it, the record does not
    assert_eq!(reason(&transcript(&block(1, 9, 0, &[]), 1, &[])), at(RECORD));

    // padding after the value is allowed; a value past the block is not
    let s = parse_spdm(&transcript(&block(1, 6, 0, &[0, 0, 0]), 1, &[])).ok().unwrap();
    assert_eq!(s.measurements, [(1, vec![])]);
    let s = parse_spdm(&transcript(&block(2, 6, 3, &[4, 5, 6]), 1, &[])).ok().unwrap();
    assert_eq!(s.measurements, [(2, vec![4, 5, 6])]);
    assert_eq!(reason(&transcript(&block(1, 6, 4, &[4, 5, 6]), 1, &[])), at(DMTF));
}

#[test]
fn an_opaque_tlv_header_may_end_the_opaque_data_exactly() {
    let s = parse_spdm(&transcript(&[], 0, &[3, 0, 0, 0])).ok().unwrap();
    assert_eq!(s.opaque.get(&3), Some(&vec![]));
    assert_eq!(reason(&transcript(&[], 0, &[3, 0, 0])), at("truncated opaque TLV header"));
}

// ---- the VBIOS version

#[test]
fn js_slice_is_javascripts() {
    let cases: &[(&str, i64, i64, &str)] = &[
        ("abcdef", -2, 6, "ef"),
        ("abc", -10, 2, "ab"),
        ("abc", 0, 2, "ab"),
        ("abc", 1, 99, "bc"),
        ("abc", 2, 1, ""),
        ("abc", -1, -1, ""),
    ];
    for (s, a, b, want) in cases {
        assert_eq!(js_slice(s, *a, *b), *want, "{s} {a} {b}");
    }
    assert_eq!(format_vbios_version(&[1, 2, 3, 4]), "02.01.03");
    assert_eq!(format_vbios_version(&[0xab]), "b");
}

// ---- the device chain

#[test]
fn the_root_must_be_both_a_ca_and_self_signed() {
    const NOT_ROOT: Option<&str> = Some("device chain root is not a self-signed CA");
    let run = |der: &[u8]| verify_device_chain(&pem(der), &[spki(der)], NOW).err();

    let self_signed_ca = mint(Curve::P384, 1, 1, &good_ca());
    assert_eq!(run(&self_signed_ca), None);
    let self_signed_leaf = mint(Curve::P384, 1, 1, &good_leaf());
    assert_eq!(run(&self_signed_leaf).as_deref(), NOT_ROOT);
    let ca_signed_elsewhere = mint(Curve::P384, 2, 1, &good_ca());
    assert_eq!(run(&ca_signed_elsewhere).as_deref(), NOT_ROOT);
}

// ---- RIM ids

fn spdm(opaque: &[(u16, &[u8])], measurements: Vec<(u8, Vec<u8>)>) -> Spdm {
    Spdm {
        request_version: 0x11,
        response_version: 0x11,
        request_nonce: vec![],
        measurements,
        opaque: opaque.iter().map(|(k, v)| (*k, v.to_vec())).collect(),
        signature: vec![],
        signed: vec![],
    }
}

const NAMING: [(u16, &[u8]); 5] = [(3, b"550.54"), (6, &[1, 2, 3, 4]), (17, b"P"), (18, b"S"), (15, b"C")];

#[test]
fn a_report_needs_every_naming_field() {
    let ids = rim_ids_for_report(&spdm(&NAMING, vec![])).unwrap();
    assert_eq!((ids.chip.as_str(), ids.driver_version.as_str(), ids.vbios_version.as_str()), ("GH100", "550.54", "02.01.03"));
    for skip in 0..NAMING.len() {
        let some: Vec<(u16, &[u8])> = NAMING.iter().enumerate().filter(|(i, _)| *i != skip).map(|(_, f)| *f).collect();
        assert!(rim_ids_for_report(&spdm(&some, vec![])).is_none(), "without opaque field {}", NAMING[skip].0);
    }
}

/// attest-nvidia-rim.ts:282: `^[A-Z][A-Z0-9]{2,11}$`.
#[test]
fn chip_info_table() {
    let chip = |raw: &[u8]| {
        let mut o = NAMING.to_vec();
        o.push((35, raw));
        rim_ids_for_report(&spdm(&o, vec![])).map(|i| i.chip)
    };
    for good in ["ABC", "GB100", "G12345678901", "A00"] {
        assert_eq!(chip(good.as_bytes()).as_deref(), Some(good));
    }
    assert_eq!(chip(b"GB100\0\0").as_deref(), Some("GB100"));
    for bad in ["", "AB", "G123456789012", "1BC", "GBa", "G-1", "gb100"] {
        assert_eq!(chip(bad.as_bytes()), None, "{bad:?}");
    }
}

// ---- comparison with the RIMs

fn rim_of(golden: &[(i64, &str)]) -> VerifiedRim {
    let golden: BTreeMap<i64, Golden> = golden.iter().map(|(i, h)| (*i, Golden { index: *i, active: true, size: h.len() / 2, hashes: vec![h.to_string()] })).collect();
    VerifiedRim { product: "GH100".into(), version: "1".into(), golden }
}

const DIFFER: &str = "runtime measurements differ from the golden RIM values at 1 index(es)";

#[test]
fn the_rims_may_list_as_many_measurements_as_the_report_carries() {
    let run = |golden: &[(i64, &str)], m: Vec<(u8, Vec<u8>)>| compare_report_to_rims(&spdm(&[], m), &rim_of(golden), &rim_of(&[]));
    assert_eq!(run(&[(0, "aa")], vec![(1, vec![0xaa])]), Ok(()));
    assert_eq!(run(&[(0, "aa"), (1, "bb")], vec![(1, vec![0xaa])]), Err("RIMs list more active measurements than the report carries".to_string()));
}

/// attest-nvidia-rim.ts:311 and :315: golden index 34 is block 35, skipped only when opaque field 11 starts with 0x55.
#[test]
fn only_block_35_is_skipped_and_only_when_nvdec0_is_disabled() {
    let run = |index: i64, opaque: &[(u16, &[u8])]| {
        let block = index as u8 + 1;
        compare_report_to_rims(&spdm(opaque, vec![(block, vec![0xbb])]), &rim_of(&[(index, "aa")]), &rim_of(&[]))
    };
    let differ = Err(DIFFER.to_string());
    assert_eq!(run(34, &[]), differ);
    assert_eq!(run(34, &[(11, &[0x55])]), Ok(()));
    assert_eq!(run(34, &[(11, &[0x54])]), differ);
    assert_eq!(run(34, &[(11, &[])]), differ);
    assert_eq!(run(33, &[(11, &[0x55])]), differ);
    assert_eq!(run(35, &[(11, &[0x55])]), differ);
}

// ---- revocation

/// A CRL revokes only the certificate its issuer issued (attest-nvidia-rim.ts:356-360). `chain` is leaf (serial 3), CA (2), root (1).
#[test]
fn a_crl_reaches_only_the_certificate_just_below_its_issuer() {
    let certs: Vec<Cert> = chain_of(Curve::P256, &[good_ca(), good_ca(), good_leaf()]).iter().map(|d| Cert::from_der(d).unwrap()).collect();
    let run = |issuer_seed: u8, serial: u8| check_chain_revocation(&certs, &[signed_crl(issuer_seed, &[&[serial]])], NOW, &[]);
    let revoked = Err("chain certificate '' is revoked".to_string());
    assert_eq!(run(2, 3), revoked, "the CA's CRL lists the leaf");
    assert_eq!(run(1, 2), revoked, "the root's CRL lists the CA");
    assert_eq!(run(2, 2), Ok(()), "the CA's CRL lists the CA");
    assert_eq!(run(1, 3), Ok(()), "the root's CRL lists the leaf");
    assert_eq!(run(1, 1), Ok(()), "the root's CRL lists the root");
    assert_eq!(run(3, 3), Ok(()), "a CRL signed by the leaf has nothing below it");
}

// ---- versions and the chip name

/// attest-nvidia-rim.ts:410: `^\d+(\.\d+)*$` and `^[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*$`.
#[test]
fn parse_version_table() {
    let cases: &[(&str, u32, Option<&[u64]>)] = &[
        ("1.2", 10, Some(&[1, 2][..])),
        ("0012", 10, Some(&[12][..])),
        ("", 10, None),
        ("1.", 10, None),
        ("+5", 10, None),
        ("a", 10, None),
        ("abcd.1", 16, Some(&[0xabcd, 1][..])),
        ("", 16, None),
        ("abcde", 16, None),
        ("+1", 16, None),
        ("g", 16, None),
    ];
    for (v, radix, want) in cases {
        assert_eq!(parse_version(v, *radix).as_deref(), *want, "{v} {radix}");
    }
}

/// attest-nvidia-rim.ts:457: `(^|[^A-Za-z0-9])chip([^A-Za-z0-9]|$)`.
#[test]
fn chip_in_subject_table() {
    for (subject, chip) in [("GH100", "GH100"), ("CN=GH100,O=x", "GH100"), ("GH100 x", "GH100"), ("x GH100", "GH100"), ("xGH100 GH100", "GH100"), ("-", "-")] {
        assert!(chip_in_subject(subject, chip), "{subject} {chip}");
    }
    for (subject, chip) in [("", "GH100"), ("GH1", "GH100"), ("GB100 x", "GH100"), ("xGH100", "GH100"), ("GH100x", "GH100"), ("xGH100x", "GH100"), ("-", ""), ("", "")] {
        assert!(!chip_in_subject(subject, chip), "{subject:?} {chip:?}");
    }
}

/// k05 deadline: the opaque TLV walk advances past each header and value.
#[test]
fn the_opaque_tlv_walk_terminates() {
    let t = transcript(&[], 0, &[3, 0, 2, 0, 0xaa, 0xbb, 4, 0, 1, 0, 0xcc]);
    let s = crate::k042_support::within("parse_spdm opaque", move || parse_spdm(&t).ok().map(|s| s.opaque));
    assert_eq!(s.map(|o| o.len()), Some(2));
}
