//! Self-tests of the attestation building blocks against fixtures minted with an independent implementation (OpenSSL via
//! the Python `cryptography` package): ECDSA P-256 / P-384, RSA PKCS#1 v1.5 and RSASSA-PSS, X.509 parsing, the strict DER
//! readers, the validity window and the binding hash.

use atlas_pca::attest::der::{check_chain_roles, der_validity_ms, parse_cert_extensions, parse_der_time, parse_tbs_extensions, read_cert_role_info, read_tlv, tbs_of_certificate, unrecognised_critical_extension, x509_valid_at};
use atlas_pca::attest::util::{b64_lenient, b64_std, b64url_enc, hex_decode, hex_lower, parse_iso_ms};
use atlas_pca::attest::x509::{ecdsa_der_to_raw, ecdsa_verify_raw, parse_spki, pem_blocks, rsa_pkcs1_verify, rsa_pss_verify, verify_der_sig, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use atlas_pca::attest::{attestation_binding, Binding};
use std::collections::HashSet;

const MSG: &[u8] = b"atlas attestation selftest";
const P256_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004539cbbe83ddeb0dc674a2df204cb7d7d3eb461e67679b81659575fa154c0c85cd65dbcdddb3c793ecf20e7d8a0959fa58ef675a3d2408bacd2ada54c4cc0a0ad";
const P256_DER: &str = "3046022100a2283cbffe5c1abe2e2a253143add55039d89f24eedebd214640e9f2488e378b022100e0ae69a0036d4df02043c7fb8a0dfdfccbc39b5988c0064e3c18533b062f1f1e";
const P256_RAW: &str = "a2283cbffe5c1abe2e2a253143add55039d89f24eedebd214640e9f2488e378be0ae69a0036d4df02043c7fb8a0dfdfccbc39b5988c0064e3c18533b062f1f1e";
const P384_SPKI: &str = "3076301006072a8648ce3d020106052b810400220362000474b9de5ed33ca65400f8baf2a32b8c6a21bf5b60db7dd40b12117a321e35cf766be5c9055330c182c1d95c5386735116a89ba3f8651b871ad4114e81d4eb056d62e16d6c6143f0e4ac0c88cffa21c70d6651fabfafad8aaafc3129ed1dd07ef6";
const P384_DER: &str = "30650231009b63d41b0b97b2a8f5d2c5b995a1cdcec3ed0cbad77acf8144b193bd226e56dedc0f9121f4ae5854e298b257d202ca0f023031fc8e144251a0a074e4333b48e1ac2405bf4d00d7b99f7507ef406c743c1fb014f21834aa321c8501b8f60ee987e39a";
const P384_RAW: &str = "9b63d41b0b97b2a8f5d2c5b995a1cdcec3ed0cbad77acf8144b193bd226e56dedc0f9121f4ae5854e298b257d202ca0f31fc8e144251a0a074e4333b48e1ac2405bf4d00d7b99f7507ef406c743c1fb014f21834aa321c8501b8f60ee987e39a";
const RSA_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100c1788adf3b603013efc5c2be4801bbb7e60dbe14f3be22f244194d8b249c3ee722b1c3c9354e02fb536865ccfb0521b32904841a8ed7c34ac7d9c370edc4b0a339748dc495543e670e50d9d5c7d561a65c82c5098fe0130dd6a4df8111475c27b1a8aa21878a5a3f4ebc55f5d9d26a40c3e88d9a5535228d4d1243b2a7ff50e7cdf912fce9bd9a36b6b563e6bfbcd413334d0e02d24f7fbcfe1012211dfc6c0e027039c39a6f5fdcb38aaa83705aaa00e49bf19f855a82f47c0e82366c4981e6419b92f5eb486bcacb81acefb6adb6cd548f15da0e2480756f74ef16f63fc27027d531474cae055293e0f882e510f55a2965754b8f0139dbd8ffc473e8d2212f0203010001";
const RSA_PKCS1: &str = "29c4762cb48b7acf8ef02a9890c2fe4319be14137eedaa2fd92c95d19f06a75c43d71d415ff89847917dbdb4c4648384fa4bd8c1c7cf54cfe6e0a1222ec153404f51e1b9818896e56051a814c7eaf9d0ad46def029a6ac237420cf6dc9448393f90449ea64b72e21fd6a91cfac8d1643406f991926343c5957a4093d5504e9025f19019941250af51de9b7be1784a16ff83778934b28b14f6cf245862270d92609651d955693a807d50a1a0352661e1894d76ca193f942a7f48c001a06a4c03ba54bf74ec322aa886e734763878636a839582cad0f80e901af73829be9ad34469e816624f56de862e6ffca5e48dc6e0980c867679155273efefad680c8cbcf09";
const RSA_PSS: &str = "a984e1dd44c6e02b3f0e4212ad8052aec4b420182632903a24aedc4c907e473c2ae3502b68be6c59e42bc17b36c8e22628bfc2110447eb72f6ef49344906787f1cfd727d1ca3273349002a0f782a40edb9a28e67da04a3a4c6828dceb588fdedd5192f20569b511d733c5b0f879ed2ace01e021ae77513cf38e8ed43ac174c83e45518453d1d166ef42f7f3d008a5d2ae72eec0292de8fe162ac470ec06ee800aaf6a5be4d2d7d124ee3b970031b74c8422e79d5b5b642c6951df0ecfb068e600c4b9c4919890cc92506a4b10b3752855faaf7bc85e6a3beca071e8bf3624d104488c6a18f2284731d2fa8def761bc0391c1c2c5dabece7fafef93f0ad0ae422";
const ROOT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBwDCCAUegAwIBAgIFAQIDBAUwCgYIKoZIzj0EAwMwNjELMAkGA1UEBhMCVVMx
EzARBgNVBAoMCkF0bGFzIFRlc3QxEjAQBgNVBAMMCVRlc3QgUm9vdDAgFw0yMDAx
MDEwMDAwMDBaGA8yMDYwMDEwMTAwMDAwMFowNjELMAkGA1UEBhMCVVMxEzARBgNV
BAoMCkF0bGFzIFRlc3QxEjAQBgNVBAMMCVRlc3QgUm9vdDB2MBAGByqGSM49AgEG
BSuBBAAiA2IABNErmwt6YRKPWg3SSIzK/Y8M1WR3N0meTmkVcEitotU6n0W6Sn07
QSle89lVO5dudl0DVhBuKJff1K68ex/3HXoP4tfRlO3sDhD5mznGYMbSdGxODk2N
cIg7UskJwfAW66MjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYw
CgYIKoZIzj0EAwMDZwAwZAIwWz5C7q/VlGTklWPoH1922Uf1nzt5JbCttl8Q0Xlb
txLNE3g7JZYw8+36rdGEbexaAjADGwmfqErAcpz8Qu5V8t9vRAmVEPjia0x7p0ZV
e8YmPWuzbVNFb91bihlfkuNx2Og=
-----END CERTIFICATE-----
"#;
const LEAF_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBqzCCATGgAwIBAgICAP8wCgYIKoZIzj0EAwMwNjELMAkGA1UEBhMCVVMxEzAR
BgNVBAoMCkF0bGFzIFRlc3QxEjAQBgNVBAMMCVRlc3QgUm9vdDAgFw0yMDAxMDEw
MDAwMDBaGA8yMDYwMDEwMTAwMDAwMFowNjELMAkGA1UEBhMCVVMxEzARBgNVBAoM
CkF0bGFzIFRlc3QxEjAQBgNVBAMMCVRlc3QgTGVhZjB2MBAGByqGSM49AgEGBSuB
BAAiA2IABOz/gPlecJG2K3c6zdN9SUyz+JFet3f8BLcbspVlXoYhgJj7ZaDb5m9m
8PAkgZhJ1sMJVFFa5jRyozcOfxzoDSEtXW10mVpsfVNo9OPHvZc+nTSWm6+eB7dq
gdDU6FxMdKMQMA4wDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAwNoADBlAjAmStwZ
WdU6PrskGPypicZSo4e5IEnAu9YuygF9GEm6e47odtR9FCoPD8mo7/DYK/gCMQD8
5SHaNLQN5bGec07F+2sV46YnhpHZXCFDjuQHjY1IWYi+m1FqZzmhee7eQScPU+c=
-----END CERTIFICATE-----
"#;
const ROOT_PIN: &str = "6562cf3153b8180013e75f1e3993d631056ff5541d1eb1bd36728cabda66f99d";
const RSAROOT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDdjCCAiqgAwIBAgIFAQIDBAUwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQME
AgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEwMDUxCzAJBgNV
BAYTAlVTMRMwEQYDVQQKDApBdGxhcyBUZXN0MREwDwYDVQQDDAhSU0EgUm9vdDAg
Fw0yMDAxMDEwMDAwMDBaGA8yMDYwMDEwMTAwMDAwMFowNTELMAkGA1UEBhMCVVMx
EzARBgNVBAoMCkF0bGFzIFRlc3QxETAPBgNVBAMMCFJTQSBSb290MIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsf8bARJRA/6j8PEXsyX2a3/dX/H9D4dz
+O5rYzNy+/raaPwqi8yzyzB7tfosyvhS2wa3KDgF62Em/VzgcKymZfQZtSoJ1ZM0
mLJSMgBXVGL2YGeA/8b2b+i0ltwb+0K15ugvF0nSWkDPBZHr4Q/5Q+2aBlNdb11j
hr5Qn5M1VvlyI/uKgx60Ot/yiHhI30Z5ia7g1wzM04fx54Nb1rSZMieStiX+cEuY
mxxVtwErEIHaZewvj2QEg00a26hmBjPbI3fd8G0PhvTGAxBwaY/ycHCAqafZXx0u
dKK/P2XHRSTQgSWUGUxk0t2s/+JT2fe3tOczYFzmm0xDHs+A0w/rnQIDAQABoyMw
ITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjBBBgkqhkiG9w0BAQow
NKAPMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUA
ogMCATADggEBAJR3AiSewnHMHIZg/wkHw11A9KHyzxK7ba8E+RvJiPSm48jdVYmD
eWm7MARECcy+NB51EwT4zuWW1gtNVCy6qB9EKOKoR4gl7j/F2vugciZw6ZSAhfUS
3g9bN4dpMAc4bAOBwaLQ11fu8Vao6eFVHoIKJDzJJHoosQ8KvLVgtOgr9WY1UBJ8
XQs3SUR48YdG5cn7PYYLSfwGBsJsrXUT8AVZ3XTkKqg0wdaLX0X/XVqutjnEQnR+
RAzQLBCDeNPh+IFqTRFJxKxFlRQ6dmxcSjUdPwNWHh5Liq4PBGLoDppNskAMGOTO
hyMJc0/x3fguFTV3j/UxikXZjfppBl9qgMA=
-----END CERTIFICATE-----
"#;
const RSALEAF_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICsTCCAWWgAwIBAgIBBzBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAgUA
oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATAwNTELMAkGA1UEBhMC
VVMxEzARBgNVBAoMCkF0bGFzIFRlc3QxETAPBgNVBAMMCFJTQSBSb290MCAXDTIw
MDEwMTAwMDAwMFoYDzIwNjAwMTAxMDAwMDAwWjA1MQswCQYDVQQGEwJVUzETMBEG
A1UECgwKQXRsYXMgVGVzdDERMA8GA1UEAwwIUlNBIExlYWYwdjAQBgcqhkjOPQIB
BgUrgQQAIgNiAAQM1SWzfppdsNlXngX/4qLD8zrrUNyo/62EafqtIDIGb3JZpanm
LA0Exg0bCM0E+lVlFZqhogZU6K1AjzCJicd/FXddvuUHUU41RBBswoq68oQbx1gi
8UudYkeHr6KJvEujEDAOMAwGA1UdEwEB/wQCMAAwQQYJKoZIhvcNAQEKMDSgDzAN
BglghkgBZQMEAgIFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgIFAKIDAgEw
A4IBAQBGXQUA/tZZKPMz0IvcETWdhZXChrwgsEASpnLJcUYuCDiaZBRH9elvJm4A
IBYsYuv+hMisApn5oeJ5lAZSTFDHlg6REXuDr5IiL0SrWtadJKCh0e6G/E4vO2XF
C7yMg/+t19Ucob7O+t/3w5bsi/tESLBnJELbUYpM9JVkBH4nWcgHeeC4IDrQHRhY
xtblMLb9eMGSzXw2B7+Jog0u2QTcjytOLqCHK3cTxnfof2jKW0pEiVEBRJ1vcO7l
l0yfNIi/3/p3RjVPVFwUlJdHbKNZnWsEgupsX93s2f3FA2oMZakQp5JinHofP35Y
R4sOraFaSd32HfZqBB0kjqHbaEhs
-----END CERTIFICATE-----
"#;
const RSAP1_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDEDCCAfigAwIBAgIFAQIDBAUwDQYJKoZIhvcNAQELBQAwNjELMAkGA1UEBhMC
VVMxEzARBgNVBAoMCkF0bGFzIFRlc3QxEjAQBgNVBAMMCVJTQTEgUm9vdDAgFw0y
MDAxMDEwMDAwMDBaGA8yMDYwMDEwMTAwMDAwMFowNjELMAkGA1UEBhMCVVMxEzAR
BgNVBAoMCkF0bGFzIFRlc3QxEjAQBgNVBAMMCVJTQTEgUm9vdDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBALH/GwESUQP+o/DxF7Ml9mt/3V/x/Q+Hc/ju
a2Mzcvv62mj8KovMs8swe7X6LMr4UtsGtyg4BethJv1c4HCspmX0GbUqCdWTNJiy
UjIAV1Ri9mBngP/G9m/otJbcG/tCteboLxdJ0lpAzwWR6+EP+UPtmgZTXW9dY4a+
UJ+TNVb5ciP7ioMetDrf8oh4SN9GeYmu4NcMzNOH8eeDW9a0mTInkrYl/nBLmJsc
VbcBKxCB2mXsL49kBINNGtuoZgYz2yN33fBtD4b0xgMQcGmP8nBwgKmn2V8dLnSi
vz9lx0Uk0IEllBlMZNLdrP/iU9n3t7TnM2Bc5ptMQx7PgNMP650CAwEAAaMjMCEw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQAD
ggEBALHHq3/5/b+ZIY8RawOiHN71RFOC6FkeDsDcc2rwoD2YbZ8xcZCiGxaxe4Z7
Vg7Arg5HybJt8e7hpaVTYcvSt2iSxGQueVbWqTCBKLVr68aLvQcIwbtVupDrw2+m
dp83/7tLU4wiCOAovRAcYeyg/zdSgenS0F1oMb34/iRn4m5r7tK/KSCXhWd0vVqY
XsvB4TbZkwRPBnq/skpmWfDvZZyndg9mFiw8kNMUpavNQIx6hsbtG+15xFKhf43J
KAycdzhKS6lq3AKUhtG0eUehx9GWJ7nJaho5cj1B1N2dw+or6DNn2p2Zhv75iCsC
fP8YFUwUxFfe+1jnPDq2peuDqg8=
-----END CERTIFICATE-----
"#;

fn h(s: &str) -> Vec<u8> {
    hex_decode(s).expect("hex")
}
fn key(spki_hex: &str) -> PubKey {
    parse_spki(&h(spki_hex)).expect("spki")
}
fn flip(mut b: Vec<u8>, at: usize) -> Vec<u8> {
    b[at] ^= 1;
    b
}

#[test]
fn ecdsa_p256_verifies_der_and_raw_signatures_and_refuses_tampering() {
    let k = key(P256_SPKI);
    assert!(matches!(&k, PubKey::Ec { curve, .. } if *curve == EcCurve::P256));
    assert_eq!(k.spki_der(), h(P256_SPKI), "the canonical re-encoding equals the original SPKI");
    assert!(verify_der_sig(&k, Hash::Sha256, MSG, &h(P256_DER)));
    assert!(verify_p1363_sig(&k, Hash::Sha256, MSG, &h(P256_RAW)));
    assert_eq!(ecdsa_der_to_raw(&h(P256_DER), 32).unwrap(), h(P256_RAW));
    assert!(!verify_der_sig(&k, Hash::Sha256, b"another message", &h(P256_DER)));
    assert!(!verify_der_sig(&k, Hash::Sha256, MSG, &flip(h(P256_DER), 10)));
    assert!(!verify_p1363_sig(&k, Hash::Sha256, MSG, &flip(h(P256_RAW), 40)));
    assert!(!verify_p1363_sig(&k, Hash::Sha256, MSG, &h(P256_RAW)[..63]), "a short signature is refused");
    assert!(!verify_p1363_sig(&k, Hash::Sha256, MSG, &[0u8; 64]), "r = s = 0 is refused");
    // the wrong curve never verifies
    assert!(!verify_der_sig(&key(P384_SPKI), Hash::Sha256, MSG, &h(P256_DER)));
}

#[test]
fn ecdsa_p384_verifies_and_refuses_tampering() {
    let k = key(P384_SPKI);
    assert!(matches!(&k, PubKey::Ec { curve, .. } if *curve == EcCurve::P384));
    assert_eq!(k.spki_der(), h(P384_SPKI));
    assert!(verify_der_sig(&k, Hash::Sha384, MSG, &h(P384_DER)));
    assert!(verify_p1363_sig(&k, Hash::Sha384, MSG, &h(P384_RAW)));
    assert!(!verify_p1363_sig(&k, Hash::Sha256, MSG, &h(P384_RAW)), "the digest is part of what is signed");
    assert!(!verify_p1363_sig(&k, Hash::Sha384, MSG, &flip(h(P384_RAW), 70)));
    if let PubKey::Ec { curve, point } = &k {
        assert!(ecdsa_verify_raw(*curve, point, &atlas_pca::attest::util::sha384(MSG), &h(P384_RAW)));
        let mut bad = point.clone();
        bad[5] ^= 1;
        assert!(!ecdsa_verify_raw(*curve, &bad, &atlas_pca::attest::util::sha384(MSG), &h(P384_RAW)), "an off-curve point verifies nothing");
    }
}

#[test]
fn ecdsa_der_signatures_must_be_strict_der() {
    let good = h(P256_DER);
    assert!(ecdsa_der_to_raw(&good, 32).is_some());
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(ecdsa_der_to_raw(&trailing, 32).is_none(), "trailing bytes");
    assert!(ecdsa_der_to_raw(&good[..good.len() - 1], 32).is_none(), "truncated");
    assert!(ecdsa_der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01], 32).is_none(), "a negative integer");
    assert!(ecdsa_der_to_raw(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01], 32).is_none(), "a non-minimal integer");
    assert!(ecdsa_der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], 32).is_some());
}

#[test]
fn rsa_pkcs1_and_pss_verify_and_refuse_tampering() {
    let k = key(RSA_SPKI);
    let (n, e) = match &k {
        PubKey::Rsa { n, e } => (n.clone(), e.clone()),
        _ => panic!("not an RSA key"),
    };
    assert_eq!(k.spki_der(), h(RSA_SPKI));
    assert!(rsa_pkcs1_verify(&n, &e, Hash::Sha256, MSG, &h(RSA_PKCS1)));
    assert!(!rsa_pkcs1_verify(&n, &e, Hash::Sha384, MSG, &h(RSA_PKCS1)), "the hash is part of the signed DigestInfo");
    assert!(!rsa_pkcs1_verify(&n, &e, Hash::Sha256, b"other", &h(RSA_PKCS1)));
    assert!(!rsa_pkcs1_verify(&n, &e, Hash::Sha256, MSG, &flip(h(RSA_PKCS1), 3)));
    assert!(rsa_pss_verify(&n, &e, Hash::Sha384, 48, MSG, &h(RSA_PSS)));
    assert!(!rsa_pss_verify(&n, &e, Hash::Sha384, 32, MSG, &h(RSA_PSS)), "the salt length is exact");
    assert!(!rsa_pss_verify(&n, &e, Hash::Sha256, 48, MSG, &h(RSA_PSS)));
    assert!(!rsa_pss_verify(&n, &e, Hash::Sha384, 48, MSG, &flip(h(RSA_PSS), 9)));
    assert!(!rsa_pss_verify(&n, &e, Hash::Sha384, 48, MSG, &h(RSA_PKCS1)), "one scheme's signature is not the other's");
    assert!(verify_der_sig(&k, Hash::Sha256, MSG, &h(RSA_PKCS1)), "node's generic verify on an RSA key is PKCS#1 v1.5");
}

fn der_of(pem: &str) -> Vec<u8> {
    atlas_pca::attest::x509::pem_to_der(pem).expect("pem")
}

#[test]
fn a_certificate_chain_parses_names_keys_and_verifies() {
    let root = Cert::from_pem(ROOT_PEM).expect("root");
    let leaf = Cert::from_pem(LEAF_PEM).expect("leaf");
    let root_key = root.public_key().unwrap();
    let leaf_key = leaf.public_key().unwrap();
    assert_eq!(root.subject_string(), "C=US\nO=Atlas Test\nCN=Test Root");
    assert_eq!(root.issuer_string(), root.subject_string());
    assert_eq!(leaf.issuer_string(), "C=US\nO=Atlas Test\nCN=Test Root");
    assert_eq!(leaf.subject_string(), "C=US\nO=Atlas Test\nCN=Test Leaf");
    assert_eq!(root_key.spki_sha256_hex(), ROOT_PIN);
    assert_eq!(root.serial_hex().trim_start_matches('0'), "102030405");
    assert_eq!(leaf.serial_hex(), "00FF");
    assert!(root.is_ca());
    assert!(!leaf.is_ca());
    assert!(root.verify(&root_key), "the root is self-signed");
    assert!(leaf.verify(&root_key), "the leaf is signed by the root");
    assert!(!leaf.verify(&leaf_key), "the leaf is not self-signed");
    assert!(!root.verify(&leaf_key));
    // a flipped signature bit and a flipped body bit both break the signature (the certificate may still parse)
    let mut bad_sig = der_of(LEAF_PEM);
    let last = bad_sig.len() - 1;
    bad_sig[last] ^= 1;
    assert!(!Cert::from_der(&bad_sig).unwrap().verify(&root_key));
    let mut bad_body = der_of(LEAF_PEM);
    let at = bad_body.windows(9).position(|w| w == b"Test Leaf").expect("subject text") + 2;
    bad_body[at] ^= 1;
    assert!(!Cert::from_der(&bad_body).unwrap().verify(&root_key));
    let both = format!("{LEAF_PEM}\n# comment\n{ROOT_PEM}");
    assert_eq!(pem_blocks(&both).len(), 2);
    assert!(Cert::from_pem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----").is_err());
    assert!(Cert::from_der(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
    assert!(Cert::from_der(&[]).is_err());
}

#[test]
fn rsa_pss_and_pkcs1_certificates_verify() {
    let root = Cert::from_pem(RSAROOT_PEM).expect("rsa root");
    let leaf = Cert::from_pem(RSALEAF_PEM).expect("leaf under an RSA root");
    let rk = root.public_key().unwrap();
    assert!(matches!(&rk, PubKey::Rsa { .. }));
    assert!(root.verify(&rk), "an RSASSA-PSS (SHA-384, salt 48) self-signed root");
    assert!(leaf.verify(&rk));
    assert!(!leaf.verify(&leaf.public_key().unwrap()));
    let p1 = Cert::from_pem(RSAP1_PEM).expect("pkcs1 cert");
    assert!(p1.verify(&p1.public_key().unwrap()), "sha256WithRSAEncryption");
    assert!(!p1.verify(&key(RSA_SPKI)), "another RSA key does not verify it");
}

#[test]
fn certificate_validity_is_read_from_the_der_with_inclusive_bounds() {
    let root = der_of(ROOT_PEM);
    let (from, to) = der_validity_ms(&root);
    assert_eq!((from, to), (Some(1_577_836_800_000), Some(2_840_140_800_000)));
    let (f, t) = (1_577_836_800_000f64, 2_840_140_800_000f64);
    assert!(x509_valid_at(&root, f, 0.0));
    assert!(!x509_valid_at(&root, f - 1.0, 0.0));
    assert!(x509_valid_at(&root, t, 0.0));
    assert!(!x509_valid_at(&root, t + 1.0, 0.0));
    assert!(x509_valid_at(&root, f - 1000.0, 1000.0), "skew widens the window");
    assert!(!x509_valid_at(&root, f - 1001.0, 1000.0));
    assert!(!x509_valid_at(&root, f64::NAN, 0.0), "an unparseable clock is never valid");
    assert!(!x509_valid_at(&[0x30, 0x00], f, 0.0), "an unparseable certificate is never valid");
}

#[test]
fn der_time_follows_the_rfc_5280_profile_without_roll_over() {
    let ok = [
        (0x17, "491231235959Z", Some(2_524_607_999_000i64)),
        (0x17, "500101000000Z", Some(-631_152_000_000)),
        (0x18, "20300101000000Z", Some(1_893_456_000_000)),
        (0x18, "20240229120000Z", Some(1_709_208_000_000)),
    ];
    for (tag, text, want) in ok {
        assert_eq!(parse_der_time(tag, text), want, "{text}");
    }
    let bad: [(u8, &str); 14] = [
        (0x17, "20300101000000Z"),
        (0x18, "300101000000Z"),
        (0x17, "491232235959Z"),
        (0x17, "491301235959Z"),
        (0x17, "490230235959Z"),
        (0x18, "20230229120000Z"),
        (0x18, "20300101240000Z"),
        (0x18, "20300101006000Z"),
        (0x18, "20300101000060Z"),
        (0x17, "4912312359Z"),
        (0x17, "491231235959+0100"),
        (0x17, "49123123595aZ"),
        (0x18, "20300101000000.5Z"),
        (0x04, "491231235959Z"),
    ];
    for (tag, text) in bad {
        assert_eq!(parse_der_time(tag, text), None, "{text}");
    }
}

#[test]
fn the_tlv_reader_refuses_every_non_minimal_or_overrunning_form() {
    let cases: [(&[u8], &str); 9] = [
        (&[0x30], "DER: truncated header"),
        (&[0x1f, 0x00], "DER: multi-byte tags are not supported"),
        (&[0x30, 0x80], "DER: unsupported length form"),
        (&[0x30, 0x84, 0, 0, 0, 1], "DER: unsupported length form"),
        (&[0x30, 0x82, 0x00], "DER: truncated length"),
        (&[0x30, 0x82, 0x00, 0x90], "DER: non-minimal length (leading zero)"),
        (&[0x30, 0x81, 0x05, 1, 2, 3, 4, 5], "DER: non-minimal length (long form below 128)"),
        (&[0x30, 0x05, 1, 2], "DER: element overruns its parent"),
        (&[0x30, 0x81, 0x80, 1], "DER: element overruns its parent"),
    ];
    for (b, want) in cases {
        assert_eq!(read_tlv(b, 0, b.len()).unwrap_err(), want, "{b:02x?}");
    }
    let t = read_tlv(&[0x30, 0x02, 0xaa, 0xbb], 0, 4).unwrap();
    assert_eq!((t.tag, t.start, t.end), (0x30, 2, 4));
    let t = read_tlv(&[0x04, 0x81, 0x80].iter().copied().chain(std::iter::repeat(0).take(128)).collect::<Vec<u8>>(), 0, 131).unwrap();
    assert_eq!((t.start, t.end), (3, 131));
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    atlas_pca::attest::x509::der_wrap(tag, body)
}
fn ext(oid: &[u8], critical: Option<u8>, value: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x06, oid);
    if let Some(c) = critical {
        body.extend(tlv(0x01, &[c]));
    }
    body.extend(tlv(0x04, value));
    tlv(0x30, &body)
}
const BC: [u8; 3] = [0x55, 0x1d, 0x13];
const KU: [u8; 3] = [0x55, 0x1d, 0x0f];
/// A minimal tbsCertificate carrying the given `[3]` extensions block bodies.
fn tbs_with(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = tlv(0x02, &[1]);
    for b in blocks {
        body.extend(tlv(0xa3, b));
    }
    tlv(0x30, &body)
}
fn cert_with(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = tbs_with(blocks);
    body.extend(tlv(0x30, &[]));
    body.extend(tlv(0x03, &[0]));
    tlv(0x30, &body)
}
fn exts(list: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &list.concat())
}
fn ca_cert(path_len: Option<u8>, ku: Option<u8>) -> Vec<u8> {
    let mut bc = tlv(0x01, &[0xff]);
    if let Some(p) = path_len {
        bc.extend(tlv(0x02, &[p]));
    }
    let mut list = vec![ext(&BC, Some(0xff), &tlv(0x30, &bc))];
    if let Some(k) = ku {
        list.push(ext(&KU, Some(0xff), &tlv(0x03, &[0, k])));
    }
    cert_with(&[exts(&list)])
}
fn leaf_cert() -> Vec<u8> {
    cert_with(&[exts(&[ext(&BC, Some(0xff), &tlv(0x30, &[]))])])
}

#[test]
fn the_extension_table_is_read_strictly() {
    let ok = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&BC, Some(0xff), &tlv(0x30, &[])), ext(&KU, None, &tlv(0x03, &[0, 0x04]))])])).unwrap();
    assert_eq!(ok.len(), 2);
    assert_eq!((ok[0].oid.as_str(), ok[0].critical), ("2.5.29.19", true));
    assert_eq!((ok[1].oid.as_str(), ok[1].critical), ("2.5.29.15", false));
    let dup = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&BC, None, &[]), ext(&BC, None, &[])])]));
    assert_eq!(dup.unwrap_err(), "duplicate extension 2.5.29.19");
    let flag = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&BC, Some(0x01), &[])])]));
    assert_eq!(flag.unwrap_err(), "extension 2.5.29.19 has a non-DER critical flag");
    let explicit_false = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&BC, Some(0x00), &[])])]));
    assert_eq!(explicit_false.unwrap_err(), "extension 2.5.29.19 has a non-DER critical flag");
    let empty = parse_tbs_extensions(&tbs_with(&[tlv(0x30, &[])]));
    assert_eq!(empty.unwrap_err(), "empty Extensions SEQUENCE");
    let two = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&BC, None, &[])]), exts(&[ext(&KU, None, &[])])]));
    assert_eq!(two.unwrap_err(), "duplicate [3] extensions block");
    let mut trailing_ext = ext(&BC, None, &[]);
    trailing_ext.pop();
    assert!(parse_tbs_extensions(&tbs_with(&[exts(&[trailing_ext])])).is_err());
    let mut with_junk = tbs_with(&[exts(&[ext(&BC, None, &[])])]);
    with_junk.push(0);
    assert_eq!(parse_tbs_extensions(&with_junk).unwrap_err(), "trailing bytes after tbsCertificate");
    // an OID that merely appears inside another extension's value is not an extension
    let hidden = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&KU, None, &tlv(0x06, &BC))])])).unwrap();
    assert_eq!(hidden.len(), 1);
    assert_eq!(parse_tbs_extensions(&tbs_with(&[])).unwrap().len(), 0);
    let weird_oid = parse_tbs_extensions(&tbs_with(&[exts(&[ext(&[0x55, 0x80, 0x01], None, &[])])]));
    assert_eq!(weird_oid.unwrap_err(), "extension OID has a non-minimal arc");
}

#[test]
fn certificate_role_info_and_chain_roles() {
    let ca = read_cert_role_info(&ca_cert(Some(3), Some(0x04))).unwrap();
    assert!(ca.has_basic_constraints && ca.ca && ca.has_key_usage && ca.key_cert_sign);
    assert_eq!(ca.path_len, Some(3));
    let leaf = read_cert_role_info(&leaf_cert()).unwrap();
    assert!(leaf.has_basic_constraints && !leaf.ca && !leaf.has_key_usage);
    let mut trailing = leaf_cert();
    trailing.push(0);
    assert_eq!(read_cert_role_info(&trailing).unwrap_err(), "trailing bytes after the certificate");
    let bad_bit = cert_with(&[exts(&[ext(&KU, None, &tlv(0x03, &[9, 0x04]))])]);
    assert_eq!(read_cert_role_info(&bad_bit).unwrap_err(), "keyUsage BIT STRING has more than 7 unused bits");

    let (root, mid, leaf) = (ca_cert(None, Some(0x04)), ca_cert(Some(0), Some(0x04)), leaf_cert());
    assert_eq!(check_chain_roles(&[leaf.clone(), root.clone()]), None);
    assert_eq!(check_chain_roles(&[root.clone()]), None, "a bare root has no relationship to check");
    assert_eq!(check_chain_roles(&[leaf.clone(), mid.clone(), root.clone()]), None, "pathLen 0 admits no intermediate below it, one is the leaf");
    assert_eq!(check_chain_roles(&[leaf.clone(), root.clone(), root.clone()]), None);
    assert_eq!(check_chain_roles(&[root.clone(), root.clone()]).unwrap(), "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)");
    assert_eq!(check_chain_roles(&[leaf.clone(), leaf.clone()]).unwrap(), "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)");
    let no_bc = cert_with(&[exts(&[ext(&KU, None, &tlv(0x03, &[0, 0x04]))])]);
    assert_eq!(check_chain_roles(&[leaf.clone(), no_bc]).unwrap(), "issuer certificate at depth 1 has no BasicConstraints (not a CA)");
    let no_sign = ca_cert(None, Some(0x80));
    assert_eq!(check_chain_roles(&[leaf.clone(), no_sign]).unwrap(), "issuer certificate at depth 1 keyUsage lacks keyCertSign");
    assert_eq!(
        check_chain_roles(&[leaf.clone(), mid.clone(), mid.clone(), root.clone()]).unwrap(),
        "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"
    );
    let mut junk = leaf.clone();
    junk.push(1);
    assert_eq!(check_chain_roles(&[junk, root]).unwrap(), "certificate extension parse failed: trailing bytes after the certificate");
}

#[test]
fn critical_extensions_the_verifier_does_not_understand_are_reported() {
    let weird = cert_with(&[exts(&[ext(&BC, Some(0xff), &tlv(0x30, &[])), ext(&[0x2a, 0x03], Some(0xff), &[])])]);
    assert_eq!(unrecognised_critical_extension(&weird, None).unwrap(), Some("1.2.3".to_string()));
    assert_eq!(unrecognised_critical_extension(&leaf_cert(), None).unwrap(), None);
    let none: HashSet<String> = HashSet::new();
    assert_eq!(unrecognised_critical_extension(&leaf_cert(), Some(&none)).unwrap(), Some("2.5.29.19".to_string()));
    let all: HashSet<String> = ["1.2.3".to_string(), "2.5.29.19".to_string()].into_iter().collect();
    assert_eq!(unrecognised_critical_extension(&weird, Some(&all)).unwrap(), None);
    assert!(unrecognised_critical_extension(&[0x30, 0x00], None).is_err());
}

#[test]
fn the_real_certificate_extensions_and_tbs_are_extracted() {
    let root = der_of(ROOT_PEM);
    let exts = parse_cert_extensions(&root).unwrap();
    let bc = exts.iter().find(|e| e.oid == "2.5.29.19").expect("basicConstraints");
    assert!(bc.critical);
    let ku = exts.iter().find(|e| e.oid == "2.5.29.15").expect("keyUsage");
    assert!(ku.critical);
    let tbs = tbs_of_certificate(&root).unwrap();
    assert_eq!(tbs[0], 0x30);
    assert!(root.windows(tbs.len()).any(|w| w == tbs.as_slice()));
    let mut trailing = root.clone();
    trailing.push(0);
    assert_eq!(tbs_of_certificate(&trailing).unwrap_err(), "trailing bytes after the certificate");
    assert!(read_cert_role_info(&root).unwrap().ca);
}

#[test]
fn the_binding_hash_is_pinned_and_refuses_unconstructible_bindings() {
    let b = Binding { holder_pub: "holder-key".into(), grant_ref: "grant-ref-1".into(), epoch: 3.0, nonce: "nonce-123".into() };
    assert_eq!(hex_lower(&attestation_binding(&b).unwrap()), "b06e6ce4763c4f2e9f7269f4d7f5bd83029477b45d3cc36cf4ece1c7d8f72070db70fc364f7cb9e631fb529f8bee29c3c9e30af88c3c25ba54b2bdf1bf50d409");
    let same = attestation_binding(&b).unwrap();
    for other in [
        Binding { holder_pub: "holder-keyx".into(), ..b.clone() },
        Binding { grant_ref: "grant-ref-2".into(), ..b.clone() },
        Binding { epoch: 4.0, ..b.clone() },
        Binding { nonce: "nonce-124".into(), ..b.clone() },
    ] {
        assert_ne!(attestation_binding(&other).unwrap(), same);
    }
    let cases = [
        (Binding { holder_pub: String::new(), ..b.clone() }, "binding: holderPub required"),
        (Binding { grant_ref: String::new(), ..b.clone() }, "binding: grantRef required"),
        (Binding { nonce: String::new(), ..b.clone() }, "binding: nonce required"),
        (Binding { epoch: -1.0, ..b.clone() }, "binding: epoch must be a non-negative safe integer"),
        (Binding { epoch: 1.5, ..b.clone() }, "binding: epoch must be a non-negative safe integer"),
        (Binding { epoch: 9_007_199_254_740_992.0, ..b.clone() }, "binding: epoch must be a non-negative safe integer"),
        (Binding { epoch: f64::NAN, ..b.clone() }, "binding: epoch must be a non-negative safe integer"),
    ];
    for (bad, want) in cases {
        assert_eq!(attestation_binding(&bad).unwrap_err(), want);
    }
    assert!(attestation_binding(&Binding { epoch: 0.0, ..b.clone() }).is_ok());
    assert!(attestation_binding(&Binding { epoch: 9_007_199_254_740_991.0, ..b }).is_ok());
}

#[test]
fn encoding_helpers_match_node() {
    assert_eq!(b64_lenient("AQID"), vec![1, 2, 3]);
    assert_eq!(b64_lenient("AQI"), vec![1, 2], "unpadded");
    assert_eq!(b64_lenient("AQI="), vec![1, 2]);
    assert_eq!(b64_lenient("A Q\nI D"), vec![1, 2, 3], "whitespace is skipped");
    assert_eq!(b64_lenient("-_-_"), b64_lenient("+/+/"), "both alphabets");
    assert_eq!(b64_std(&[1, 2]), "AQI=");
    assert_eq!(b64_std(&[]), "");
    assert_eq!(b64url_enc(&[0xfb, 0xff]), "-_8");
    assert_eq!(hex_decode("0aFf").unwrap(), vec![0x0a, 0xff]);
    assert!(hex_decode("abc").is_none());
    assert_eq!(parse_iso_ms("2026-01-01T00:00:00Z"), Some(1_767_225_600_000));
    assert_eq!(parse_iso_ms("2026-01-01T00:00:00.5Z"), Some(1_767_225_600_500));
    assert_eq!(parse_iso_ms("2026-02-30T00:00:00Z"), None);
    assert_eq!(parse_iso_ms("2026-01-01"), None);
    assert_eq!(parse_iso_ms("soon"), None);
}
