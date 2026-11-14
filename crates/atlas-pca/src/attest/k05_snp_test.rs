//! hardware-sevsnp.ts and attest-amd-snp.ts, one wrong clause at a time. Chains and reports are really signed, so each input reaches
//! the clause it targets.

use super::{check_policy, decode_spl, parse_report, parse_u64_policy, report_sig_valid, verify_amd_cert_chain, SnpVerifier, REPORT_LEN, SIGNED_END, SIG_R, SIG_S};
use crate::attest::k05_cert_support::{ca_ext, cert_sign_ext, cn, ext_block, leaf_ext, oid_alg, point_p256, point_p384, sign_p384, spki_p256, spki_p384, Parts, ECDSA_SHA384, TO_MS};
use crate::attest::util::b64_std;
use crate::attest::x509::{Cert, EcCurve, PubKey};
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};

#[test]
fn u32_fields_are_little_endian_at_their_offsets() {
    let raw: Vec<u8> = (0..REPORT_LEN).map(|i| i as u8).collect();
    let r = parse_report(&raw).unwrap();
    assert_eq!(r.guest_svn, 0x0706_0504);
    assert_eq!(r.vmpl, 0x3332_3130);
    assert_eq!(r.signature_algo, 0x3736_3534);
}

/// A report signed by P-384 key `seed`, with AMD's little-endian r and s.
fn signed_report(seed: u8) -> Vec<u8> {
    let mut raw = vec![0u8; REPORT_LEN];
    raw[0] = 2;
    let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().sign(&raw[..SIGNED_END]);
    let rs = sig.to_bytes().to_vec();
    for i in 0..48 {
        raw[SIG_R + i] = rs[47 - i];
        raw[SIG_S + i] = rs[95 - i];
    }
    raw
}

#[test]
fn the_report_signature_needs_p384_and_zero_high_bytes_in_both_scalars() {
    let raw = signed_report(7);
    let key = PubKey::Ec { curve: EcCurve::P384, point: point_p384(7) };
    let verdict = |b: &[u8], k: &PubKey| report_sig_valid(&parse_report(b).unwrap(), k);
    assert!(verdict(&raw, &key));
    assert!(!verdict(&raw, &PubKey::Ec { curve: EcCurve::P384, point: point_p384(8) }));
    assert!(!verdict(&raw, &PubKey::Ec { curve: EcCurve::P256, point: point_p256(7) }));
    assert!(!verdict(&raw, &PubKey::Rsa { n: vec![1], e: vec![1] }));
    for at in [SIG_R + 48, SIG_R + 71, SIG_S + 48, SIG_S + 71] {
        let mut b = raw.clone();
        b[at] = 1;
        assert!(!verdict(&b, &key), "byte {at:#x}");
    }
}

#[test]
fn spl_values_are_minimal_der_integers_up_to_255() {
    const NOT_INT: &str = "is not a DER INTEGER";
    const WRONG_LEN: &str = "has a wrong-length INTEGER";
    let cases: [(&[u8], Result<i64, &str>); 17] = [
        (&[], Err(NOT_INT)),
        (&[0x02, 0x01], Err(NOT_INT)),
        (&[0x01, 0x01, 0x05], Err(NOT_INT)),
        (&[0x02, 0x00, 0x00], Err(WRONG_LEN)),
        (&[0x02, 0x03, 0x00, 0x80, 0x00], Err(WRONG_LEN)),
        (&[0x02, 0x01, 0x05, 0x05], Err(WRONG_LEN)),
        (&[0x02, 0x02, 0x05], Err(WRONG_LEN)),
        (&[0x02, 0x01, 0x80], Err("is negative")),
        (&[0x02, 0x02, 0x80, 0x80], Err("is negative")),
        (&[0x02, 0x02, 0x01, 0x00], Err("is out of range (> 255)")),
        (&[0x02, 0x02, 0x01, 0x80], Err("is out of range (> 255)")),
        (&[0x02, 0x02, 0x00, 0x7f], Err("is a non-minimal INTEGER")),
        (&[0x02, 0x02, 0x00, 0x00], Err("is a non-minimal INTEGER")),
        (&[0x02, 0x01, 0x00], Ok(0)),
        (&[0x02, 0x01, 0x7f], Ok(0x7f)),
        (&[0x02, 0x02, 0x00, 0x80], Ok(0x80)),
        (&[0x02, 0x02, 0x00, 0xff], Ok(0xff)),
    ];
    for (v, want) in cases {
        assert_eq!(decode_spl(v), want, "{v:?}");
    }
}

fn pem(der: &[u8]) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64_std(der))
}

/// VCEK (with this key), the ASK + ARK bundle and the ARK pin, all ECDSA P-384 signed.
fn amd_chain(vcek_spki: Vec<u8>) -> (Vec<u8>, String, String) {
    const ARK_SEED: u8 = 1;
    const ASK_SEED: u8 = 2;
    let sign_with = |seed: u8, p: &Parts| p.cert(&sign_p384(seed, &p.tbs()));
    let part = |spki: Vec<u8>, issuer: &[u8], subject: &[u8], exts: &[Vec<u8>]| {
        let mut p = Parts::new(spki).alg(oid_alg(ECDSA_SHA384));
        p.issuer = cn(issuer);
        p.subject = cn(subject);
        p.after_spki = ext_block(exts);
        p
    };
    let ca = [ca_ext(), cert_sign_ext()];
    let ark = sign_with(ARK_SEED, &part(spki_p384(ARK_SEED), b"ark", b"ark", &ca));
    let ask = sign_with(ARK_SEED, &part(spki_p384(ASK_SEED), b"ark", b"ask", &ca));
    let vcek = sign_with(ASK_SEED, &part(vcek_spki, b"ask", b"vcek", &[leaf_ext()]));
    let pin = Cert::from_der(&ark).unwrap().public_key().unwrap().spki_sha384_hex();
    (vcek, format!("{}{}", pem(&ask), pem(&ark)), pin)
}

#[test]
fn the_skew_widens_the_end_of_the_validity_window() {
    let (vcek, bundle, pin) = amd_chain(spki_p384(3));
    let run = |now: f64, skew: f64| verify_amd_cert_chain(&vcek, &bundle, &pin, now, Some(skew)).map(|_| ());
    assert_eq!(run(TO_MS, 0.0), Ok(()));
    assert_eq!(run(TO_MS + 1000.0, 2000.0), Ok(()));
    assert_eq!(run(TO_MS + 3000.0, 2000.0), Err("VCEK certificate has expired".to_string()));
}

#[test]
fn a_vcek_on_another_curve_is_named_in_the_refusal() {
    let (vcek, bundle, pin) = amd_chain(spki_p256(3));
    assert_eq!(verify_amd_cert_chain(&vcek, &bundle, &pin, TO_MS, None).map(|_| ()), Err("AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)".to_string()));
}

#[test]
fn tcb_floors_convert_as_big_int_does() {
    // attestation-wire.ts:188: a present floor goes through BigInt(), so null throws rather than meaning no floor.
    assert_eq!(parse_u64_policy(&Value::Null), Err("Cannot convert null to a BigInt".to_string()));
    assert_eq!(parse_u64_policy(&json!(5)), Ok(Some(5)));
    assert_eq!(parse_u64_policy(&json!(1.5)), Err("The number 1.5 cannot be converted to a BigInt because it is not an integer".to_string()));
    assert_eq!(parse_u64_policy(&json!("7")), Ok(Some(7)));
    assert_eq!(parse_u64_policy(&json!("")), Ok(Some(0)));
}

/// A policy with these extra members, its measurement matching an all-zero report.
fn verifier(extra: Value) -> SnpVerifier {
    let mut policy = json!({"measurements": ["00".repeat(48)]});
    for (k, v) in extra.as_object().unwrap() {
        policy[k] = v.clone();
    }
    let cfg = json!({"family": "milan", "binding": "report-data", "policy": policy});
    SnpVerifier::from_config(cfg.as_object().unwrap()).ok().unwrap()
}

/// An all-zero report (signature_algo 1), this u64 at `at`.
fn report_with(at: usize, value: u64) -> Vec<u8> {
    let mut raw = vec![0u8; REPORT_LEN];
    raw[0x34] = 1;
    raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
    raw
}

#[test]
fn a_tcb_at_its_floor_passes_and_one_below_does_not() {
    for (key, at, why) in [
        ("minReportedTcb", 0x180, "reported_tcb below minimum (rollback?)"),
        ("minCommittedTcb", 0x1e0, "committed_tcb below minimum (rollback?)"),
        ("minLaunchTcb", 0x1f0, "launch_tcb below minimum"),
    ] {
        let v = verifier(json!({ key: "5" }));
        assert_eq!(check_policy(&parse_report(&report_with(at, 5)).unwrap(), &v.policy), None, "{key}");
        assert_eq!(check_policy(&parse_report(&report_with(at, 4)).unwrap(), &v.policy).as_deref(), Some(why), "{key}");
    }
}

#[test]
fn only_the_word_any_waives_the_vmpl() {
    let mut raw = report_with(0x180, 0);
    raw[0x30] = 3;
    let report = parse_report(&raw).unwrap();
    let reason = |want: Value| check_policy(&report, &verifier(json!({ "requireVmpl": want })).policy);
    assert_eq!(reason(json!("any")), None);
    assert_eq!(reason(json!(3)), None);
    // The reference prints String(requireVmpl) (hardware-sevsnp.ts:694).
    assert_eq!(reason(json!(0)).as_deref(), Some("vmpl 3 is not the required 0"));
    assert_eq!(reason(json!("ANY")).as_deref(), Some("vmpl 3 is not the required ANY"));
    assert_eq!(reason(json!(true)).as_deref(), Some("vmpl 3 is not the required true"));
}
