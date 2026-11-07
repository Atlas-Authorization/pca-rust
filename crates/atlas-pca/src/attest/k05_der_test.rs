//! The strict readers of x509-strict.ts and x509-validity.ts, one wrong clause at a time. Reasons are the reference's own text.

use super::{parse_der_time, parse_digits, parse_tbs_extensions, read_cert_role_info, read_tlv, tlv_at, x509_valid_at, der_validity_ms};
use crate::attest::k05_cert_support::{ext, ext_block, FROM_MS, TO_MS};
use crate::attest::x509::der_wrap as tlv;

#[test]
fn read_tlv_tells_a_short_long_form_from_a_leading_zero() {
    assert_eq!(read_tlv(&[0x30, 0x81, 0x00], 0, 3).unwrap_err(), "DER: non-minimal length (long form below 128)");
    assert_eq!(read_tlv(&[0x30, 0x82, 0x00, 0x80], 0, 4).unwrap_err(), "DER: non-minimal length (leading zero)");
    let body = vec![0u8; 0x0102];
    let t = read_tlv(&tlv(0x30, &body), 0, 4 + 0x0102).unwrap();
    assert_eq!((t.start, t.end), (4, 4 + 0x0102));
}

/// A certificate holding this BasicConstraints content, followed by another extension, so a read past the content stays in the buffer.
fn role_cert(bc: &[Vec<u8>]) -> Vec<u8> {
    let exts = [ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &bc.concat())), ext(&[0x2a, 0x03], false, &[0x05, 0x00])];
    tlv(0x30, &tlv(0x30, &ext_block(&exts)))
}

#[test]
fn a_path_length_is_a_positive_integer_of_one_or_two_bytes() {
    let ca = tlv(0x01, &[0xff]);
    for (name, pl) in [
        ("wrong tag", tlv(0x04, &[1])),
        ("empty", tlv(0x02, &[])),
        ("three bytes", tlv(0x02, &[1, 2, 3])),
        ("negative", tlv(0x02, &[0x80])),
    ] {
        assert_eq!(read_cert_role_info(&role_cert(&[ca.clone(), pl])).unwrap_err(), "BasicConstraints pathLenConstraint malformed", "{name}");
    }
    for (content, want) in [(vec![0u8], 0), (vec![0x7f], 0x7f), (vec![1, 2], 0x0102), (vec![1, 0], 0x0100), (vec![0x7f, 0xff], 0x7fff)] {
        let info = read_cert_role_info(&role_cert(&[ca.clone(), tlv(0x02, &content)])).unwrap();
        assert_eq!(info.path_len, Some(want), "{content:?}");
        assert!(info.ca);
    }
}

fn tbs_with(exts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, &[1]), ext_block(exts)].concat())
}

#[test]
fn the_critical_flag_is_exactly_one_0xff() {
    let flagged = |flag: Vec<u8>| tlv(0x30, &[tlv(0x06, &[0x2a, 0x03, 0x04]), flag, tlv(0x04, &[])].concat());
    for bad in [tlv(0x01, &[0xff, 0xff]), tlv(0x01, &[]), tlv(0x01, &[0x00]), tlv(0x01, &[0x01])] {
        assert_eq!(parse_tbs_extensions(&tbs_with(&[flagged(bad)])).unwrap_err(), "extension 1.2.3.4 has a non-DER critical flag");
    }
    let good = parse_tbs_extensions(&tbs_with(&[flagged(tlv(0x01, &[0xff]))])).unwrap();
    assert!(good[0].critical);
}

#[test]
fn an_extension_oid_renders_as_openssl_does() {
    for (oid, dotted) in [
        (vec![0x05u8], "0.5"),
        (vec![0x27], "0.39"),
        (vec![0x28], "1.0"),
        (vec![0x2d], "1.5"),
        (vec![0x4f], "1.39"),
        (vec![0x50], "2.0"),
        (vec![0x5a], "2.10"),
        (vec![0x2a, 0x03, 0x04], "1.2.3.4"),
        (vec![0x2a, 0x86, 0x48, 0x05], "1.2.840.5"),
        (vec![0x88, 0x37, 0x01], "2.999.1"),
    ] {
        let exts = parse_tbs_extensions(&tbs_with(&[ext(&oid, false, &[])])).unwrap();
        assert_eq!(exts[0].oid, dotted, "{oid:?}");
    }
}

#[test]
fn tlv_at_takes_up_to_four_length_octets_inside_the_buffer() {
    let ok = |b: &[u8]| tlv_at(b, 0).map(|t| (t.start, t.end));
    assert_eq!(ok(&[0x30, 0x00]), Ok((2, 2)), "a header ending the buffer");
    assert_eq!(ok(&[0x30]), Err(()));
    assert_eq!(ok(&[0x30, 0x80, 0, 0, 0, 0, 0]), Err(()), "indefinite");
    assert_eq!(ok(&[0x30, 0x84, 0, 0, 0, 1, 0xaa]), Ok((6, 7)), "four octets");
    assert_eq!(ok(&[0x30, 0x85, 0, 0, 0, 0, 1, 0xaa]), Err(()), "five octets");
    assert_eq!(ok(&[0x30, 0x82, 0, 0]), Ok((4, 4)), "length octets ending the buffer");
    assert_eq!(ok(&[0x30, 0x82, 0]), Err(()), "length octets past the buffer");
}

#[test]
fn parse_digits_takes_only_digits() {
    assert_eq!(parse_digits(b"042"), Some(42));
    assert_eq!(parse_digits(b""), None);
    assert_eq!(parse_digits(b"1a"), None);
    assert_eq!(parse_digits(b"/"), None);
    assert_eq!(parse_der_time(0x17, "/20101000000Z"), None);
}

/// The fields of a TBS ahead of `validity`, with no version.
fn before_validity() -> Vec<u8> {
    [tlv(0x02, &[1]), tlv(0x30, &[]), tlv(0x30, &[])].concat()
}

fn window() -> Vec<u8> {
    tlv(0x30, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat())
}

#[test]
fn validity_must_be_a_sequence_inside_the_tbs() {
    const BOTH: (Option<i64>, Option<i64>) = (Some(FROM_MS as i64), Some(TO_MS as i64));
    let whole = |tbs: Vec<u8>| tlv(0x30, &tbs);
    assert_eq!(der_validity_ms(&whole(tlv(0x30, &[before_validity(), window(), tlv(0x30, &[])].concat()))), BOTH);
    assert_eq!(der_validity_ms(&whole(tlv(0x30, &[before_validity(), window()].concat()))), BOTH, "validity ending the TBS");

    let set = tlv(0x31, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat());
    assert_eq!(der_validity_ms(&whole(tlv(0x30, &[before_validity(), set].concat()))), (None, None), "a SET");
    let outside = [tlv(0x30, &before_validity()), window()].concat();
    assert_eq!(der_validity_ms(&tlv(0x30, &outside)), (None, None), "validity after the end of the TBS");
}

#[test]
fn valid_at_is_the_closed_window_widened_by_the_skew() {
    let der = tlv(0x30, &tlv(0x30, &[before_validity(), window()].concat()));
    let mid = (FROM_MS + TO_MS) / 2.0;
    for (now, skew, want) in [
        (mid, 0.0, true),
        (FROM_MS, 0.0, true),
        (TO_MS, 0.0, true),
        (FROM_MS - 1.0, 0.0, false),
        (TO_MS + 1.0, 0.0, false),
        (TO_MS + 1000.0, 2000.0, true),
        (TO_MS + 3000.0, 2000.0, false),
        (FROM_MS - 1000.0, 2000.0, true),
        (FROM_MS - 3000.0, 2000.0, false),
        (mid, f64::INFINITY, false),
        (mid, f64::NAN, false),
        (f64::INFINITY, 0.0, false),
        (f64::NEG_INFINITY, 0.0, false),
        (f64::NAN, 0.0, false),
    ] {
        assert_eq!(x509_valid_at(&der, now, skew), want, "now {now} skew {skew}");
    }
}
