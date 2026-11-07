//! The X.509 reader against Node's `X509Certificate` (the TypeScript verifiers' reader): every expected rendering and acceptance below
//! was read from Node. Signatures are real, so a verdict turns on the one clause each input breaks.

use super::{
    asn1_err, der_wrap, ec_point_valid, ecdsa_der_to_raw, name_to_string, parse_spki, pem_blocks, pem_public_key, pss_params, rsa_pkcs1_verify, tlv_in, verify_p1363_sig, Cert, EcCurve, Hash, PubKey,
};
use crate::attest::k05_cert_support::{cn, ext, ext_block, name_of, oid_alg, point_p256, point_p384, rdn, sign_p256, sign_p256_prehash, spki_p256, Parts, ECDSA_SHA256, ECDSA_SHA384, ECDSA_SHA512, EC_KEY, P256_CURVE};
use crate::attest::util::{b64_std, hex_decode, sha512};
use super::der_wrap as tlv;
use rsa::BigUint;

#[test]
fn curves_carry_nodes_names() {
    assert_eq!(EcCurve::P256.node_name(), Some("prime256v1"));
    assert_eq!(EcCurve::P384.node_name(), Some("secp384r1"));
    assert_eq!(EcCurve::P521.node_name(), Some("secp521r1"));
    assert_eq!(EcCurve::Other.node_name(), None);
}

#[test]
fn der_wrap_uses_the_shortest_length_form() {
    let cases: [(usize, &[u8]); 9] = [
        (0, &[4, 0]),
        (0x7f, &[4, 0x7f]),
        (0x80, &[4, 0x81, 0x80]),
        (0x81, &[4, 0x81, 0x81]),
        (0xff, &[4, 0x81, 0xff]),
        (0x100, &[4, 0x82, 1, 0]),
        (0xffff, &[4, 0x82, 0xff, 0xff]),
        (0x10000, &[4, 0x83, 1, 0, 0]),
        (0x012345, &[4, 0x83, 1, 0x23, 0x45]),
    ];
    for (n, head) in cases {
        let out = der_wrap(4, &vec![0u8; n]);
        assert_eq!(&out[..head.len()], head, "{n:#x}");
        assert_eq!(out.len(), head.len() + n, "{n:#x}");
    }
}

#[test]
fn key_exports_name_what_node_names() {
    assert_eq!(PubKey::Ed25519(vec![1]).jwk_crv(), "Ed25519");
    assert!(PubKey::Ec { curve: EcCurve::Other, point: vec![4] }.spki_der().is_empty(), "no curve, no encoding");
    // crypto.generateKeyPairSync('ec', {namedCurve: 'P-521'}): SPKI export
    const P521: &str = "30819b301006072a8648ce3d020106052b81040023038186000401a0c2d8941fdfab3b9730c6792988a88a6bdffc7988076e3230a8941f5528e6c24e719f25bb37c050de1627381f9f2da276eb29c0ac57585f7c932fa704c638d53f0190645126de4ca227bca85ca394badf10db88a851d8cb0be15c3ffed6bafb3c49eace31747aa6ff8003661d227e7fa21e05789e21961986ed32c550a32607b220b1";
    let der = hex_decode(P521).unwrap();
    let key = parse_spki(&der).unwrap();
    assert_eq!(key.jwk_crv(), "P-521");
    assert_eq!(key.spki_der(), der);
}

#[test]
fn tlv_in_keeps_a_child_inside_its_limit() {
    let b = [0x30, 0x02, 1, 2];
    assert_eq!(tlv_in(&b, 0, 4).map(|t| t.end), Ok(4));
    assert_eq!(tlv_in(&b, 0, 3).map(|t| t.end), Err(asn1_err()));
}

#[test]
fn an_ec_spki_breaks_on_each_clause_alone() {
    let alg = tlv(0x30, &[tlv(0x06, EC_KEY), tlv(0x06, P256_CURVE)].concat());
    let p = point_p256(1);
    let bits = |unused: u8, key: &[u8]| tlv(0x03, &[&[unused][..], key].concat());
    let good = tlv(0x30, &[alg.clone(), bits(0, &p)].concat());
    assert!(matches!(parse_spki(&good), Ok(PubKey::Ec { curve: EcCurve::P256, .. })));

    let mut compressed = p.clone();
    compressed[0] = 0x02;
    for (name, bad) in [
        ("outer tag", tlv(0x31, &[alg.clone(), bits(0, &p)].concat())),
        ("trailing byte", [good.clone(), vec![0]].concat()),
        ("key not a BIT STRING", tlv(0x30, &[alg.clone(), tlv(0x04, &[&[0u8][..], &p[..]].concat())].concat())),
        ("element after the key", tlv(0x30, &[alg.clone(), bits(0, &p), tlv(0x05, &[])].concat())),
        ("empty BIT STRING", tlv(0x30, &[alg.clone(), tlv(0x03, &[])].concat())),
        ("unused bits", tlv(0x30, &[alg.clone(), bits(1, &p)].concat())),
        ("short point", tlv(0x30, &[alg.clone(), bits(0, &p[..64])].concat())),
        ("not uncompressed", tlv(0x30, &[alg.clone(), bits(0, &compressed)].concat())),
    ] {
        assert!(parse_spki(&bad).is_err(), "{name}");
    }
}

#[test]
fn an_rsa_spki_breaks_on_each_clause_alone() {
    const RSA: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const PSS: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    let wrap_as = |oid: &[u8], key: Vec<u8>| {
        let alg = tlv(0x30, &[tlv(0x06, oid), tlv(0x05, &[])].concat());
        tlv(0x30, &[alg, tlv(0x03, &[vec![0], key].concat())].concat())
    };
    let wrap = |key: Vec<u8>| wrap_as(&RSA, key);
    let (n, e) = (tlv(0x02, &[0, 0xc1, 2, 3]), tlv(0x02, &[1, 0, 1]));
    let seq = tlv(0x30, &[n.clone(), e.clone()].concat());
    match parse_spki(&wrap(seq.clone())) {
        Ok(PubKey::Rsa { n, e }) => {
            assert_eq!(n, vec![0xc1, 2, 3]);
            assert_eq!(e, vec![1, 0, 1]);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(parse_spki(&wrap_as(&PSS, seq.clone())), Ok(PubKey::RsaPss { .. })));

    for (name, key) in [
        ("not a SEQUENCE", tlv(0x31, &[n.clone(), e.clone()].concat())),
        ("byte after the SEQUENCE", [seq.clone(), vec![0]].concat()),
        ("n not an INTEGER", tlv(0x30, &[tlv(0x03, &[1]), e.clone()].concat())),
        ("e not an INTEGER", tlv(0x30, &[n.clone(), tlv(0x03, &[1])].concat())),
        ("element after e", tlv(0x30, &[n.clone(), e.clone(), tlv(0x05, &[])].concat())),
    ] {
        assert!(parse_spki(&wrap(key)).is_err(), "{name}");
    }
}

#[test]
fn an_ecdsa_signature_is_a_sequence_of_exactly_two_integers() {
    let int = |v: &[u8]| tlv(0x02, v);
    let sig = |parts: &[Vec<u8>]| tlv(0x30, &parts.concat());

    let mut zero_r = vec![0u8; 64];
    zero_r[63] = 1;
    assert_eq!(ecdsa_der_to_raw(&sig(&[int(&[0]), int(&[1])]), 32), Some(zero_r), "a lone zero byte is a valid r");

    assert_eq!(ecdsa_der_to_raw(&sig(&[tlv(0x03, &[1]), int(&[1])]), 32), None, "r tag");
    assert_eq!(ecdsa_der_to_raw(&sig(&[int(&[1]), tlv(0x03, &[1])]), 32), None, "s tag");
    assert_eq!(ecdsa_der_to_raw(&sig(&[int(&[1]), int(&[1]), tlv(0x05, &[])]), 32), None, "element after s");
    assert_eq!(ecdsa_der_to_raw(&sig(&[int(&[1])]), 32), None, "no s");
}

// A throwaway RSA-1024 key, generated once with node:crypto.
const RSA_N: &str = "a6edda29ca348d06a48469ef94bb3af11c3b7fb0f5f977f8ad4a09ede4cccdc43ec26e62f08a01040bb52e49312d7e6170ece8a976f77c21121f62f2ca3679925addf18447fec2af493bf911a717ecc737ddde0ba774675578fa0b7da87ebc6ba4f06bc113aee430757f471c069703888155c85bfbb0e12158d32b9d3b68a4d9";
const RSA_E: &str = "010001";
const RSA_D: &str = "65702a5fb4b9a46d41f21931f68ea42dba7b49882ea12f4f5576a57c03ca94cbc95b7b9af212dab52bac28f95f4207078d88d985897eb0d6a3dda0d26b21195463f3538d133316e27827803b62ca38b6aa4f773463489819cbdba1affe23dae78b004fe193eab5c6047a0eb0360748a23b6336138281b4ccee570bac64c6a011";
const RSA_P: &str = "da96db15665d8a352fac337530256c97b24929568036d0a914a371c6dec298084cf7e77574fd2c39964f5a52a10adfcc25a8a3750d02d54f48aa0323d2a7d6c5";
const RSA_Q: &str = "c37f966d65e818b7eb3a56f54d18a5fd7a8ca4473dfa1a8993d6e0666b1695e65481c6f99ad29811db008437fce841bb85b6a2b07b7e3178efb1460581dad705";

fn h(s: &str) -> Vec<u8> {
    hex_decode(s).unwrap()
}

pub(in crate::attest) fn rsa_pub() -> PubKey {
    PubKey::Rsa { n: h(RSA_N), e: h(RSA_E) }
}

/// The same numbers under SPKI algorithm id 1.2.840.113549.1.1.10.
pub(in crate::attest) fn rsa_pss_pub() -> PubKey {
    PubKey::RsaPss { n: h(RSA_N), e: h(RSA_E) }
}

#[test]
fn pkcs1_under_an_rsa_pss_key_is_refused_on_every_path() {
    use super::verify_der_sig;
    use crate::attest::jws::Jws;
    use crate::attest::k05_cert_support::Parts;
    let (sig, rsa, pss) = (rsa_sign(Hash::Sha256, b"m"), rsa_pub(), rsa_pss_pub());
    // the signature is good: only the key's algorithm id turns each verdict
    assert!(verify_der_sig(&rsa, Hash::Sha256, b"m", &sig));
    assert!(!verify_der_sig(&pss, Hash::Sha256, b"m", &sig));
    assert!(verify_p1363_sig(&rsa, Hash::Sha256, b"m", &sig));
    assert!(!verify_p1363_sig(&pss, Hash::Sha256, b"m", &sig));

    let jws = Jws { alg: "RS256".into(), kid: None, x5c: None, payload: Default::default(), signing_input: b"m".to_vec(), signature: sig };
    assert_eq!(crate::attest::gcp::verify_jws_signature(&jws, &rsa), Ok(()));
    assert!(crate::attest::gcp::verify_jws_signature(&jws, &pss).unwrap_err().starts_with("RS256 token but signing key is"));

    let leaf = |oid_last: u8| {
        let alg = tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, oid_last]), tlv(0x05, &[])].concat());
        let numbers = tlv(0x30, &[tlv(0x02, &[vec![0], h(RSA_N)].concat()), tlv(0x02, &h(RSA_E))].concat());
        let spki = tlv(0x30, &[alg, tlv(0x03, &[vec![0], numbers].concat())].concat());
        Cert::from_der(&Parts::new(spki).cert(&[1])).unwrap()
    };
    assert!(matches!(leaf(10).public_key(), Ok(PubKey::RsaPss { .. })));
    assert_eq!(crate::attest::maa::verify_jws_signature(&jws, &leaf(1)), Ok(()));
    assert!(crate::attest::maa::verify_jws_signature(&jws, &leaf(10)).unwrap_err().starts_with("RS256 token but signing key is"));

    // an X.509 signature with a PKCS#1 algorithm id (sha256WithRSAEncryption)
    let parts = Parts::new(crate::attest::k05_cert_support::spki_p256(1)).alg(crate::attest::k05_cert_support::oid_alg(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 11]));
    let cert = Cert::from_der(&parts.cert(&rsa_sign(Hash::Sha256, &parts.tbs()))).unwrap();
    assert!(cert.verify(&rsa));
    assert!(!cert.verify(&pss));
}

/// PKCS#1 v1.5 over `msg`.
pub(in crate::attest) fn rsa_sign(hash: Hash, msg: &[u8]) -> Vec<u8> {
    let big = |s: &str| BigUint::from_bytes_be(&h(s));
    let key = rsa::RsaPrivateKey::from_components(big(RSA_N), big(RSA_E), big(RSA_D), vec![big(RSA_P), big(RSA_Q)]).unwrap();
    let mut hashed = hash.prefix().to_vec();
    hashed.extend_from_slice(&hash.digest(msg));
    key.sign(rsa::Pkcs1v15Sign::new_unprefixed(), &hashed).unwrap()
}

#[test]
fn p1363_verification_takes_an_rsa_key_too() {
    let sig = rsa_sign(Hash::Sha256, b"m");
    assert!(rsa_pkcs1_verify(&h(RSA_N), &h(RSA_E), Hash::Sha256, b"m", &sig));
    assert!(verify_p1363_sig(&rsa_pub(), Hash::Sha256, b"m", &sig));
    assert!(!verify_p1363_sig(&rsa_pub(), Hash::Sha256, b"n", &sig));
}

#[test]
fn from_der_refuses_each_malformed_field_alone() {
    let wrong_tag = || Err(asn1_err());
    assert_eq!(asn1_err(), "error:068000A8:asn1 encoding routines::wrong tag");
    let parse = |der: &[u8]| Cert::from_der(der).map(|c| c.sig);
    let base = Parts::new(spki_p256(1));
    assert_eq!(parse(&base.cert(&[1, 2, 3])), Ok(vec![1, 2, 3]));

    let bits = tlv(0x03, &[0, 1, 2, 3]);
    let extra = tlv(0x30, &[base.tbs(), base.outer_alg.clone(), bits, tlv(0x05, &[])].concat());
    assert_eq!(parse(&extra), wrong_tag(), "element after the signature");
    assert_eq!(parse(&base.cert_with_bits(tlv(0x03, &[]))), wrong_tag(), "empty signature");

    // the serial as Node's X509Certificate reads it: parsed ones then refused ones
    let with_serial = |b: &[u8]| {
        let t = base.tbs();
        let at = t.windows(3).position(|w| w == [0x02, 0x01, 0x01]).unwrap();
        let header = if t[1] < 0x80 { 2 } else { 2 + (t[1] & 0x7f) as usize };
        let body = [&t[header..at], &tlv(0x02, b), &t[at + 3..]].concat();
        tlv(0x30, &[tlv(0x30, &body), base.outer_alg.clone(), tlv(0x03, &[0, 1])].concat())
    };
    assert_eq!(parse(&with_serial(&[1])), Ok(vec![1]));
    for ok in [&[0x11u8][..], &[0, 0x80], &[0xff, 0x7f], &[0x80], &[0], &[0x11; 21]] {
        assert_eq!(parse(&with_serial(ok)), Ok(vec![1]), "{ok:?}");
    }
    for bad in [&[0u8, 0x11][..], &[0xff, 0x80], &[0, 0], &[]] {
        assert_eq!(parse(&with_serial(bad)), wrong_tag(), "{bad:?}");
    }

    let (t, gt, int) = (tlv(0x17, b"250101000000Z"), tlv(0x18, b"20300101000000Z"), tlv(0x02, &[1]));
    let with_validity = |parts: &[Vec<u8>]| {
        let mut p = base.clone();
        p.validity = tlv(0x30, &parts.concat());
        p.cert(&[1])
    };
    assert_eq!(parse(&with_validity(&[t.clone(), gt.clone()])), Ok(vec![1]));
    assert_eq!(parse(&with_validity(&[gt.clone(), t.clone()])), Ok(vec![1]));
    assert_eq!(parse(&with_validity(&[int.clone(), t.clone()])), wrong_tag(), "notBefore");
    assert_eq!(parse(&with_validity(&[t.clone(), int.clone()])), wrong_tag(), "notAfter");
    assert_eq!(parse(&with_validity(&[t.clone(), t.clone(), t.clone()])), wrong_tag(), "a third time");
}

#[test]
fn the_fields_after_the_spki_take_openssls_order() {
    let (u1, u2) = (tlv(0x81, &[0, 0xaa]), tlv(0x82, &[0, 0xbb]));
    let ex = ext_block(&[ext(&[0x55, 0x1d, 0x13], false, &tlv(0x30, &[]))]);
    let parse = |fields: &[Vec<u8>]| {
        let mut p = Parts::new(spki_p256(1));
        p.after_spki = fields.concat();
        Cert::from_der(&p.cert(&[1])).map(|_| ())
    };
    for ok in [vec![], vec![u1.clone()], vec![u2.clone()], vec![ex.clone()], vec![u1.clone(), u2.clone()], vec![u1.clone(), ex.clone()], vec![u2.clone(), ex.clone()], vec![u1.clone(), u2.clone(), ex.clone()]] {
        assert_eq!(parse(&ok), Ok(()));
    }
    for (name, bad) in [
        ("[2] then [1]", vec![u2.clone(), u1.clone()]),
        ("[3] then [1]", vec![ex.clone(), u1.clone()]),
        ("[1] twice", vec![u1.clone(), u1.clone()]),
        ("[3] twice", vec![ex.clone(), ex.clone()]),
        ("[4]", vec![tlv(0xa4, &[])]),
        ("[3] then [4]", vec![ex.clone(), tlv(0xa4, &[])]),
    ] {
        assert_eq!(parse(&bad), Err(asn1_err()), "{name}");
    }
}

fn p256_key(seed: u8) -> PubKey {
    PubKey::Ec { curve: EcCurve::P256, point: point_p256(seed) }
}

#[test]
fn verify_needs_every_ecdsa_clause_with_a_genuine_signature() {
    let run = |p: Parts| {
        let cert = Cert::from_der(&p.cert(&sign_p256(1, &p.tbs()))).unwrap();
        cert.verify(&p256_key(1))
    };
    let base = Parts::new(spki_p256(1));
    assert!(run(base.clone()));

    let mut unused = base.clone();
    unused.unused = 1;
    assert!(!run(unused), "unused bits in the signature");

    let mut differs = base.clone();
    differs.outer_alg = tlv(0x30, &[tlv(0x06, ECDSA_SHA256), tlv(0x05, &[])].concat());
    assert!(!run(differs), "outer algorithm differs from the TBS one");

    assert!(!run(base.clone().alg(tlv(0x30, &tlv(0x05, ECDSA_SHA256)))), "the identifier is not an OID");
    assert!(!run(base.clone().alg(oid_alg(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x09, 0x02]))), "same length, another arc");
    assert!(!run(base.clone().alg(oid_alg(&[ECDSA_SHA256, &[1]].concat()))), "one arc too long");
    assert!(!run(base.clone().alg(oid_alg(&[0x2a, 0x03, 0x04]))), "a short OID");
    assert!(!run(base.clone().alg(oid_alg(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x05]))), "an unknown ECDSA hash");
    assert!(!run(base.clone().alg(oid_alg(ECDSA_SHA384))), "the signature is over SHA-256, not SHA-384");
}

#[test]
fn verify_accepts_ecdsa_with_sha512() {
    let p = Parts::new(spki_p256(1)).alg(oid_alg(ECDSA_SHA512));
    let cert = Cert::from_der(&p.cert(&sign_p256_prehash(1, &sha512(&p.tbs())))).unwrap();
    assert!(cert.verify(&p256_key(1)));
    assert!(!cert.verify(&p256_key(2)));
}

#[test]
fn verify_picks_the_pkcs1_hash_from_the_exact_oid() {
    const P: [u8; 8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    let oid = |last: u8| [&P[..], &[last]].concat();
    let run = |alg_oid: &[u8], hash: Hash| {
        let p = Parts::new(spki_p256(1)).alg(tlv(0x30, &[tlv(0x06, alg_oid), tlv(0x05, &[])].concat()));
        Cert::from_der(&p.cert(&rsa_sign(hash, &p.tbs()))).unwrap().verify(&rsa_pub())
    };
    assert!(run(&oid(11), Hash::Sha256));
    assert!(run(&oid(12), Hash::Sha384));
    assert!(run(&oid(13), Hash::Sha512));
    assert!(!run(&oid(12), Hash::Sha256), "the OID names SHA-384");
    assert!(!run(&oid(13), Hash::Sha384), "the OID names SHA-512");
    assert!(!run(&oid(14), Hash::Sha256), "an unknown PKCS#1 arc");
    assert!(!run(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x02, 0x0b], Hash::Sha256), "same length, another arc");
    assert!(!run(&[&oid(11)[..], &[0]].concat(), Hash::Sha256), "one arc too long");
}

// ---- RSASSA-PSS parameters

const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

fn hash_alg(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x06, oid), tlv(0x05, &[])].concat())
}

fn mgf(oid: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08]), hash_alg(oid)].concat())
}

fn pss(fields: &[Vec<u8>]) -> Option<(Hash, usize)> {
    let alg = tlv(0x30, &fields.concat());
    pss_params(&alg, 0, alg.len())
}

fn salt_field(content: &[u8]) -> Vec<u8> {
    tlv(0xa2, &tlv(0x02, content))
}

#[test]
fn pss_parameters_default_to_sha1_and_salt_20() {
    let alg = [1u8, 2, 3];
    assert_eq!(pss_params(&alg, 3, 3), Some((Hash::Sha1, 20)), "absent");
    assert_eq!(pss(&[]), Some((Hash::Sha1, 20)), "empty SEQUENCE");
}

#[test]
fn pss_parameters_name_each_supported_hash() {
    for (oid, hash) in [(SHA1, Hash::Sha1), (SHA256, Hash::Sha256), (SHA384, Hash::Sha384), (SHA512, Hash::Sha512)] {
        assert_eq!(pss(&[tlv(0xa0, &hash_alg(oid)), tlv(0xa1, &mgf(oid)), salt_field(&[32]), tlv(0xa3, &tlv(0x02, &[1]))]), Some((hash, 32)), "{oid:?}");
    }
    assert_eq!(pss(&[tlv(0xa0, &hash_alg(SHA256)), tlv(0xa1, &mgf(SHA384))]), None, "MGF1 with another digest");
    assert_eq!(pss(&[tlv(0xa0, &hash_alg(&[0x2a, 0x03]))]), None, "an unknown digest");
}

#[test]
fn pss_parameters_are_one_sequence_filling_the_rest_of_the_algorithm() {
    let good = tlv(0x30, &salt_field(&[32]));
    assert_eq!(pss_params(&good, 0, good.len()), Some((Hash::Sha1, 32)));
    let set = tlv(0x31, &salt_field(&[32]));
    assert_eq!(pss_params(&set, 0, set.len()), None, "a SET");
    let trailing = [good.clone(), vec![0x05, 0x00]].concat();
    assert_eq!(pss_params(&trailing, 0, trailing.len()), None, "bytes after the SEQUENCE");
}

#[test]
fn the_salt_is_a_big_endian_integer_of_at_most_four_bytes() {
    assert_eq!(pss(&[salt_field(&[0x01, 0x02])]), Some((Hash::Sha1, 0x0102)));
    assert_eq!(pss(&[salt_field(&[0x01, 0x00])]), Some((Hash::Sha1, 0x0100)));
    assert_eq!(pss(&[salt_field(&[0x01, 0, 0, 0])]), Some((Hash::Sha1, 0x0100_0000)));
    assert_eq!(pss(&[salt_field(&[0x01, 0, 0, 0, 0])]), None, "five bytes");
    assert_eq!(pss(&[tlv(0xa2, &tlv(0x04, &[32]))]), None, "not an INTEGER");
}

#[test]
fn the_trailer_field_is_the_integer_one() {
    assert_eq!(pss(&[tlv(0xa3, &tlv(0x02, &[1]))]), Some((Hash::Sha1, 20)));
    assert_eq!(pss(&[tlv(0xa3, &tlv(0x02, &[2]))]), None, "another value");
    assert_eq!(pss(&[tlv(0xa3, &tlv(0x04, &[1]))]), None, "not an INTEGER");
}

// ---- PEM

#[test]
fn pem_blocks_finds_each_block_wherever_it_starts() {
    const B1: &str = "-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----";
    const B2: &str = "-----BEGIN CERTIFICATE-----\nQg==\n-----END CERTIFICATE-----";
    // The regex of splitPemCertificates (hardware-sevsnp.ts:397) skips a stray footer and an unterminated header.
    let text = format!("junk\n-----END CERTIFICATE-----\n{B1}\nmid{B2}\n-----BEGIN CERTIFICATE-----\nunterminated");
    assert_eq!(pem_blocks(&text), vec![B1, B2]);
    assert_eq!(pem_blocks(&format!("xxxx{B1}")), vec![B1]);
}

#[test]
fn pem_public_key_reads_a_wrapped_body() {
    let b64 = b64_std(&spki_p256(1));
    let (a, b) = b64.split_at(40);
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{a}\n{b}\n-----END PUBLIC KEY-----\n");
    assert!(matches!(pem_public_key(&pem), Ok(PubKey::Ec { curve: EcCurve::P256, .. })));
    assert!(pem_public_key("not a key").is_err());
}

// ---- names: X509Certificate.subject

#[test]
fn attribute_types_render_with_openssls_short_names() {
    const EMAIL: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
    const DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
    const UID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01];
    let at = |last: u8| vec![0x55, 0x04, last];
    for (oid, want) in [
        (at(3), "CN=v"),
        (at(4), "SN=v"),
        (at(5), "serialNumber=v"),
        (at(6), "C=v"),
        (at(7), "L=v"),
        (at(8), "ST=v"),
        (at(9), "street=v"),
        (at(10), "O=v"),
        (at(11), "OU=v"),
        (at(12), "title=v"),
        (at(17), "postalCode=v"),
        (at(42), "GN=v"),
        (at(43), "initials=v"),
        (at(46), "dnQualifier=v"),
        (EMAIL.to_vec(), "emailAddress=v"),
        (DC.to_vec(), "DC=v"),
        (UID.to_vec(), "UID=v"),
    ] {
        assert_eq!(name_to_string(&name_of(&oid, 0x0c, b"v")), want);
    }
}

#[test]
fn unknown_attribute_types_render_dotted() {
    for (oid, want) in [
        (vec![0x05u8], "0.5=v"),
        (vec![0x27], "0.39=v"),
        (vec![0x28], "1.0=v"),
        (vec![0x2d], "1.5=v"),
        (vec![0x4f], "1.39=v"),
        (vec![0x50], "2.0=v"),
        (vec![0x5a], "2.10=v"),
        (vec![0x2a, 0x03, 0x04], "1.2.3.4=v"),
        (vec![0x2a, 0x86, 0x48, 0x05], "1.2.840.5=v"),
        (vec![0x88, 0x37, 0x01], "2.999.1=v"),
    ] {
        assert_eq!(name_to_string(&name_of(&oid, 0x0c, b"v")), want, "{oid:?}");
    }
}

#[test]
fn values_escape_as_openssl_does() {
    for (value, want) in [
        (" a", "CN=\\ a"),
        ("#a", "CN=\\#a"),
        ("a ", "CN=a\\ "),
        ("a#", "CN=a#"),
        ("a b", "CN=a b"),
        ("a#b", "CN=a#b"),
        (",", "CN=\\,"),
        ("+", "CN=\\+"),
        ("\"", "CN=\\\""),
        ("\\", "CN=\\\\"),
        ("<", "CN=\\<"),
        (">", "CN=\\>"),
        (";", "CN=\\;"),
        ("\u{1}", "CN=\\01"),
        ("\u{7f}", "CN=\\7F"),
        ("a\u{1f}b", "CN=a\\1Fb"),
        (" ", "CN=\\ "),
        ("  ", "CN=\\ \\ "),
        ("#", "CN=#"),
        ("é", "CN=é"),
    ] {
        assert_eq!(name_to_string(&cn(value.as_bytes())), want, "{value:?}");
    }
}

#[test]
fn string_types_decode_and_rdns_take_a_line_each() {
    const CN: &[u8] = &[0x55, 0x04, 0x03];
    let one = |tag: u8, v: &[u8]| name_to_string(&name_of(CN, tag, v));
    assert_eq!(one(0x1e, &[0x00, 0x61, 0x00, 0xe9, 0x20, 0xac]), "CN=aé€", "BMPString");
    assert_eq!(one(0x1e, &[0x01, 0x00]), "CN=Ā", "BMPString, high byte only");
    assert_eq!(one(0x13, b"p"), "CN=p");
    assert_eq!(one(0x16, b"i"), "CN=i");
    assert_eq!(one(0x14, b"t"), "CN=t");
    let two = tlv(0x30, &[rdn(&[0x55, 0x04, 0x0a], 0x0c, b"o"), rdn(CN, 0x0c, b"c")].concat());
    assert_eq!(name_to_string(&two), "O=o\nCN=c");
}

#[test]
fn a_name_ends_with_its_own_sequence() {
    let trailing = [cn(b"a"), rdn(&[0x55, 0x04, 0x0a], 0x0c, b"o")].concat();
    assert_eq!(name_to_string(&trailing), "CN=a");
}

#[test]
fn ec_point_valid_checks_each_supported_curve() {
    assert!(ec_point_valid(EcCurve::P256, &point_p256(1)));
    assert!(ec_point_valid(EcCurve::P384, &point_p384(1)));
    assert!(!ec_point_valid(EcCurve::P384, &point_p256(1)));
    assert!(!ec_point_valid(EcCurve::P521, &point_p384(1)));
}
