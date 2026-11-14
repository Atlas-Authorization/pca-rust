//! RSASSA-PSS issuer key parameter restrictions (OpenSSL `digest not allowed`): an SPKI that carries RSASSA-PSS-params admits only
//! signatures whose hash and MGF1 hash equal the key's and whose salt length is at least the key's; no params means unrestricted.
//! The signatures are real (the k05 x509 test key), so each verdict turns on the one parameter that differs.
use super::{parse_spki, Cert, Hash, PssKeyParams, PubKey};
use crate::attest::k05_cert_support::{spki_p256, Parts};
use super::k05_x509_test::{RSA_D, RSA_E, RSA_N, RSA_P, RSA_Q};
use crate::attest::util::hex_decode;
use rsa::rand_core::{CryptoRng, Error, RngCore};
use rsa::BigUint;

use super::der_wrap as tlv;

const OID_PSS: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_MGF1: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_SHA256: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// A fixed-seed generator: PSS needs a salt, the tests need determinism.
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest.iter_mut() {
            *b = (self.next_u64() >> 33) as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

fn h(s: &str) -> Vec<u8> {
    hex_decode(s).unwrap()
}

fn alg_of(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &tlv(0x06, oid))
}

/// RSASSA-PSS-params { [0] hash, [1] MGF1(mgf hash), [2] saltLength }.
fn pss_params(hash: &[u8], mgf_hash: &[u8], salt: u8) -> Vec<u8> {
    tlv(
        0x30,
        &[tlv(0xa0, &alg_of(hash)), tlv(0xa1, &tlv(0x30, &[tlv(0x06, &OID_MGF1), alg_of(mgf_hash)].concat())), tlv(0xa2, &tlv(0x02, &[salt]))].concat(),
    )
}

/// The k05 x509 test key as an SPKI with the given AlgorithmIdentifier parameters (`None` = none at all).
fn spki(params: Option<Vec<u8>>) -> Vec<u8> {
    let alg = tlv(0x30, &[tlv(0x06, &OID_PSS), params.unwrap_or_default()].concat());
    let numbers = tlv(0x30, &[tlv(0x02, &[vec![0], h(RSA_N)].concat()), tlv(0x02, &h(RSA_E))].concat());
    tlv(0x30, &[alg, tlv(0x03, &[vec![0], numbers].concat())].concat())
}

/// A certificate (subject key: any) signed with RSASSA-PSS (`hash`, MGF1 with the same hash, salt length `salt`) by the test key.
fn signed_by_pss(hash: Hash, salt: usize) -> Cert {
    let oid: &[u8] = if hash == Hash::Sha256 { &OID_SHA256 } else { &OID_SHA384 };
    let alg = tlv(0x30, &[tlv(0x06, &OID_PSS), pss_params(oid, oid, salt as u8)].concat());
    let parts = Parts::new(spki_p256(1)).alg(alg);
    let big = |s: &str| BigUint::from_bytes_be(&h(s));
    let key = rsa::RsaPrivateKey::from_components(big(RSA_N), big(RSA_E), big(RSA_D), vec![big(RSA_P), big(RSA_Q)]).unwrap();
    let digest = hash.digest(&parts.tbs());
    let sig = match hash {
        Hash::Sha256 => key.sign_with_rng(&mut TestRng(7), rsa::Pss::new_with_salt::<sha2::Sha256>(salt), &digest),
        _ => key.sign_with_rng(&mut TestRng(7), rsa::Pss::new_with_salt::<sha2::Sha384>(salt), &digest),
    }
    .unwrap();
    Cert::from_der(&parts.cert(&sig)).unwrap()
}

fn key(params: Option<Vec<u8>>) -> PubKey {
    parse_spki(&spki(params)).unwrap()
}

#[test]
fn the_params_of_the_spki_are_read() {
    let restricted = key(Some(pss_params(&OID_SHA384, &OID_SHA384, 48)));
    assert!(matches!(restricted, PubKey::RsaPss { params: PssKeyParams::Only { hash: Hash::Sha384, min_salt: 48 }, .. }), "{restricted:?}");
    assert!(matches!(key(None), PubKey::RsaPss { params: PssKeyParams::Any, .. }), "no params: unrestricted");
    assert!(matches!(key(Some(tlv(0x05, &[]))), PubKey::RsaPss { params: PssKeyParams::Any, .. }), "NULL params: unrestricted");
    // an empty SEQUENCE is the RFC 4055 defaults: SHA-1, MGF1 with SHA-1, 20 bytes of salt
    assert!(matches!(key(Some(tlv(0x30, &[]))), PubKey::RsaPss { params: PssKeyParams::Only { hash: Hash::Sha1, min_salt: 20 }, .. }));
    // a MGF1 hash that differs from the hash, or an unreadable field: no signature can satisfy it
    assert!(matches!(key(Some(pss_params(&OID_SHA384, &OID_SHA256, 48))), PubKey::RsaPss { params: PssKeyParams::Never, .. }));
    assert!(matches!(key(Some(tlv(0x30, &tlv(0xa7, &[])))), PubKey::RsaPss { params: PssKeyParams::Never, .. }));
}

#[test]
fn a_restricted_key_admits_only_its_hash_and_at_least_its_salt() {
    let k = key(Some(pss_params(&OID_SHA384, &OID_SHA384, 48)));
    assert!(signed_by_pss(Hash::Sha384, 48).verify(&k), "SHA-384, salt 48: exactly the restriction");
    assert!(signed_by_pss(Hash::Sha384, 64).verify(&k), "a longer salt is admitted");
    assert!(!signed_by_pss(Hash::Sha384, 47).verify(&k), "a shorter salt is refused");
    assert!(!signed_by_pss(Hash::Sha384, 20).verify(&k), "salt 20 is refused");
    assert!(!signed_by_pss(Hash::Sha256, 48).verify(&k), "another hash is refused");
    assert!(!signed_by_pss(Hash::Sha256, 32).verify(&k), "SHA-256 salt 32 is refused");
}

#[test]
fn an_unrestricted_key_admits_any_hash_and_salt() {
    for k in [key(None), key(Some(tlv(0x05, &[])))] {
        assert!(signed_by_pss(Hash::Sha256, 32).verify(&k));
        assert!(signed_by_pss(Hash::Sha384, 48).verify(&k));
        assert!(signed_by_pss(Hash::Sha384, 0).verify(&k));
    }
}

#[test]
fn a_key_with_unsatisfiable_params_admits_nothing() {
    let mixed = key(Some(pss_params(&OID_SHA384, &OID_SHA256, 48)));
    assert!(!signed_by_pss(Hash::Sha384, 48).verify(&mixed));
    assert!(!signed_by_pss(Hash::Sha256, 32).verify(&mixed));
    // the SHA-1 defaults: a SHA-256 signature is refused
    assert!(!signed_by_pss(Hash::Sha256, 32).verify(&key(Some(tlv(0x30, &[])))));
}
