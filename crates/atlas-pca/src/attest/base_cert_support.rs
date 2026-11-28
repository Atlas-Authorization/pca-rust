//! Test-only certificate builders for the attestation kill tests: every part can be replaced, and the result is really signed.

use super::x509::der_wrap as tlv;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;

pub(super) const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
pub(super) const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
pub(super) const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
pub(super) const EC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub(super) const P256_CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
pub(super) const P384_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// 2020-01-01T00:00:00Z and 2040-01-01T00:00:00Z, the default validity window.
pub(super) const FROM_MS: f64 = 1_577_836_800_000.0;
pub(super) const TO_MS: f64 = 2_208_988_800_000.0;

pub(super) fn oid_alg(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0x06, oid))
}

pub(super) fn point_p256(seed: u8) -> Vec<u8> {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

pub(super) fn point_p384(seed: u8) -> Vec<u8> {
    p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

fn spki_ec(curve: &[u8], point: &[u8]) -> Vec<u8> {
    let alg = tlv(0x30, &[tlv(0x06, EC_KEY), tlv(0x06, curve)].concat());
    tlv(0x30, &[alg, tlv(0x03, &[&[0u8][..], point].concat())].concat())
}

pub(super) fn spki_p256(seed: u8) -> Vec<u8> {
    spki_ec(P256_CURVE, &point_p256(seed))
}

pub(super) fn spki_p384(seed: u8) -> Vec<u8> {
    spki_ec(P384_CURVE, &point_p384(seed))
}

pub(super) fn sign_p256(seed: u8, msg: &[u8]) -> Vec<u8> {
    let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().sign(msg);
    sig.to_der().as_bytes().to_vec()
}

pub(super) fn sign_p384(seed: u8, msg: &[u8]) -> Vec<u8> {
    let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().sign(msg);
    sig.to_der().as_bytes().to_vec()
}

/// ECDSA P-256 over a digest of any supported length (DER).
pub(super) fn sign_p256_prehash(seed: u8, digest: &[u8]) -> Vec<u8> {
    let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().sign_prehash(digest).unwrap();
    sig.to_der().as_bytes().to_vec()
}

/// A `Name` of one RDN holding this attribute.
pub(super) fn name_of(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x30, &rdn(oid, tag, value))
}

pub(super) fn rdn(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x31, &tlv(0x30, &[tlv(0x06, oid), tlv(tag, value)].concat()))
}

pub(super) fn cn(value: &[u8]) -> Vec<u8> {
    name_of(&[0x55, 0x04, 0x03], 0x0c, value)
}

pub(super) fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let crit = if critical { tlv(0x01, &[0xff]) } else { vec![] };
    tlv(0x30, &[tlv(0x06, oid), crit, tlv(0x04, value)].concat())
}

/// `[3] { SEQUENCE { extensions } }`
pub(super) fn ext_block(exts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0xa3, &tlv(0x30, &exts.concat()))
}

pub(super) fn ca_ext() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &tlv(0x01, &[0xff])))
}

pub(super) fn leaf_ext() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[]))
}

pub(super) fn cert_sign_ext() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0, 0x04]))
}

/// Every part of a certificate; `Parts::new` is valid, a test replaces what it needs.
#[derive(Clone)]
pub(super) struct Parts {
    pub tbs_alg: Vec<u8>,
    pub outer_alg: Vec<u8>,
    pub issuer: Vec<u8>,
    pub validity: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    /// The optional TBS fields after the SPKI.
    pub after_spki: Vec<u8>,
    /// The signature BIT STRING's unused-bits octet.
    pub unused: u8,
}

impl Parts {
    pub(super) fn new(spki: Vec<u8>) -> Parts {
        Parts {
            tbs_alg: oid_alg(ECDSA_SHA256),
            outer_alg: oid_alg(ECDSA_SHA256),
            issuer: cn(b"a"),
            validity: tlv(0x30, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat()),
            subject: cn(b"a"),
            spki,
            after_spki: vec![],
            unused: 0,
        }
    }

    /// Both algorithm fields at once.
    pub(super) fn alg(mut self, alg: Vec<u8>) -> Parts {
        self.tbs_alg = alg.clone();
        self.outer_alg = alg;
        self
    }

    pub(super) fn tbs(&self) -> Vec<u8> {
        tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                self.tbs_alg.clone(),
                self.issuer.clone(),
                self.validity.clone(),
                self.subject.clone(),
                self.spki.clone(),
                self.after_spki.clone(),
            ]
            .concat(),
        )
    }

    /// The certificate with `sig` as the signature value.
    pub(super) fn cert(&self, sig: &[u8]) -> Vec<u8> {
        self.cert_with_bits(tlv(0x03, &[&[self.unused][..], sig].concat()))
    }

    /// The certificate with `bits` as the raw element in the signature's place.
    pub(super) fn cert_with_bits(&self, bits: Vec<u8>) -> Vec<u8> {
        tlv(0x30, &[self.tbs(), self.outer_alg.clone(), bits].concat())
    }
}
