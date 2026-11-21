//! O3 (cA must be a DER BOOLEAN: 0x00 or 0xFF) and the extension-OID content cap (x509-strict.ts, f396df8ac).
use super::*;
use crate::attest::x509::der_wrap as tlv;

fn ext(oid_content: &[u8], value: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x06, oid_content), tlv(0x04, value)].concat())
}

fn tbs_with(exts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, &[1]), tlv(0xa3, &tlv(0x30, &exts.concat()))].concat())
}

fn cert_with(exts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &[tbs_with(exts), tlv(0x30, &[]), tlv(0x03, &[0])].concat())
}

const BC: [u8; 3] = [0x55, 0x1d, 0x13];

fn basic_constraints(ca: u8) -> Vec<u8> {
    ext(&BC, &tlv(0x30, &tlv(0x01, &[ca])))
}

#[test]
fn a_ca_boolean_must_be_der() {
    let info = |ca: u8| read_cert_role_info(&cert_with(&[basic_constraints(ca)]));
    assert!(info(0xff).unwrap().ca);
    assert!(!info(0x00).unwrap().ca);
    for bad in [0x01u8, 0x02, 0x7f, 0x80, 0xfe] {
        assert_eq!(info(bad).err().as_deref(), Some("BasicConstraints cA is not a DER BOOLEAN"), "{bad:#x}");
    }
}

#[test]
fn an_extension_oid_over_256_bytes_is_refused_before_any_decoding() {
    let oid = |n: usize| vec![0x01u8; n];
    let parsed = |n: usize| parse_tbs_extensions(&tbs_with(&[ext(&oid(n), &[])]));
    assert_eq!(parsed(257).err().as_deref(), Some("extension OID is too long"));
    assert_eq!(parsed(1000).err().as_deref(), Some("extension OID is too long"));
    let ok = parsed(256).unwrap();
    assert_eq!(ok.len(), 1);
    assert!(ok[0].oid.starts_with("0.1.1.1."), "{}", ok[0].oid);
}
