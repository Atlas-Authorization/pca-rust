//! Attestation helpers against independent references: FIPS 180 for SHA-1, Node's `Buffer` for base64, `Date` for the calendar
//! (`setUTCFullYear` in parseDerTime, x509-validity.ts:69, and `Date.parse` in attest-intel-collateral.ts:260).

use super::der::parse_der_time;
use super::util::{as_obj, b64_lenient, b64_std, b64_strict, days_from_civil, days_in_month, get_obj, get_str, hex_decode, hex_lower, parse_iso_ms, sha1};
use serde_json::json;

#[test]
fn sha1_is_sha1() {
    assert_eq!(hex_lower(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn hex_decode_keeps_both_nibbles() {
    assert_eq!(hex_decode("a5"), Some(vec![0xa5]));
    assert_eq!(hex_decode("0F"), Some(vec![0x0f]));
    assert_eq!(hex_decode("f0"), Some(vec![0xf0]));
}

#[test]
fn base64_matches_node_buffer() {
    const RAW: [u8; 7] = [0xff, 0xfe, 0xfd, 0x01, 0x02, 0x03, 0x41];
    const TEXT: &str = "//79AQIDQQ==";
    assert_eq!(b64_std(&RAW), TEXT);
    assert_eq!(b64_lenient(TEXT), RAW.to_vec());
    assert_eq!(b64_strict(TEXT), Some(RAW.to_vec()));
}

#[test]
fn json_accessors_return_the_member_or_nothing() {
    let v = json!({"s": "v", "n": 1, "o": {"k": 1}});
    let m = as_obj(&v).unwrap();
    assert!(m.contains_key("s"));
    assert!(as_obj(&json!(1)).is_none());
    assert_eq!(get_str(m, "s"), Some("v"));
    assert_eq!(get_str(m, "n"), None);
    assert_eq!(get_str(m, "absent"), None);
    assert!(get_obj(m, "o").unwrap().contains_key("k"));
    assert!(get_obj(m, "n").is_none());
    assert!(get_obj(m, "absent").is_none());
}

#[test]
fn the_calendar_matches_date_at_and_below_year_zero() {
    const DAY: i64 = 86_400_000;
    // new Date(0).setUTCFullYear(y, m - 1, d)
    for (y, m, d, ms) in [
        (0, 1, 1, -62_167_219_200_000i64),
        (0, 3, 1, -62_162_035_200_000),
        (4, 2, 29, -62_035_891_200_000),
        (-1, 3, 1, -62_193_657_600_000),
        (-400, 3, 1, -74_784_816_000_000),
        (-401, 3, 1, -74_816_438_400_000),
    ] {
        assert_eq!(days_from_civil(y, m, d) * DAY, ms, "{y}-{m}-{d}");
    }
    assert_eq!(parse_der_time(0x18, "00000101000000Z"), Some(-62_167_219_200_000));
}

#[test]
fn february_follows_the_gregorian_rule() {
    for (y, days) in [(0, 29), (3, 28), (4, 29), (100, 28), (400, 29), (1600, 29), (1900, 28), (2000, 29), (2004, 29), (2023, 28), (2100, 28)] {
        assert_eq!(days_in_month(y, 2), days, "{y}");
    }
    assert_eq!(days_in_month(2023, 1), 31);
    assert_eq!(days_in_month(2023, 4), 30);
}

#[test]
fn parse_iso_ms_matches_date_parse_on_the_accepted_forms() {
    const T: i64 = 1_767_225_600_000; // Date.parse('2026-01-01T00:00:00Z')
    for (s, ms) in [
        ("2026-01-01T00:00:00Z", T),
        ("2026-01-01t00:00:00z", T),
        ("2026-01-01T00:00:00z", T),
        ("2026-01-01T00:00:00+00:00", T),
        ("2026-01-01T00:00:00-00:00", T),
        ("2026-01-01T00:00:00.5Z", T + 500),
        ("2026-01-01T00:00:00.12Z", T + 120),
        ("2026-01-01T00:00:00.123Z", T + 123),
        ("2026-01-01T00:00:00.1239Z", T + 123),
    ] {
        assert_eq!(parse_iso_ms(s), Some(ms), "{s}");
    }
}

#[test]
fn parse_iso_ms_refuses_what_date_parse_reads_as_nan() {
    for s in [
        "abc",
        "2026x01-01T00:00:00Z",
        "2026-01x01T00:00:00Z",
        "2026-01-01x00:00:00Z",
        "2026-01-01T00x00:00Z",
        "2026-01-01T00:00x00Z",
        "2026-01-01T00:00:00Q",
        "2026-01-01T00:00:00.Z",
        "2026-13-01T00:00:00Z",
    ] {
        assert_eq!(parse_iso_ms(s), None, "{s}");
    }
}

#[test]
fn parse_iso_ms_stays_strict_without_a_zone() {
    // Date.parse reads this as local time, so the verdict would depend on the box. The scan must also stop at the end of the text.
    assert_eq!(parse_iso_ms("2026-01-01T00:00:00.123"), None);
}
