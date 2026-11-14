//! The strict chain profile (`strictChainError`, x509-strict.ts:266) at each site that runs it:
//! attest-azure-maa.ts:395 and :411, attest-gcp-confidential-space.ts:384, attest-nvidia-spdm.ts:224.
//! The chains are really signed, so each one reaches the profile through the link checks.

use super::der::{strict_chain_error, unrecognised_critical_extension};
use super::gcp::{resolve_trusted_signing_key, verify_jwk_x5c_chain, GcpAnchors};
use super::jws::Jws;
use super::maa::{verify_x5c_chain, MaaAnchors, X5c};
use super::nvidia::verify_device_chain;
use super::ocsp::{delegated_issued_by, digest, key_bits, verify_ocsp_response};
use super::util::{b64_std, b64url_enc, sha1};
use super::x509::{der_wrap as tlv, Cert, Hash};
use p256::ecdsa::signature::Signer;

pub(super) const NOW: f64 = 1.8e12;
const ROOT_SEED: u8 = 1;
const OTHER_ROOT_SEED: u8 = 100;

#[derive(Clone, Copy)]
pub(super) enum Curve {
    P256,
    P384,
}

pub(super) fn point(c: Curve, seed: u8) -> Vec<u8> {
    match c {
        Curve::P256 => p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        Curve::P384 => p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().verifying_key().to_encoded_point(false).as_bytes().to_vec(),
    }
}

pub(super) fn sign(c: Curve, seed: u8, tbs: &[u8]) -> Vec<u8> {
    match c {
        Curve::P256 => {
            let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().sign(tbs);
            sig.to_der().as_bytes().to_vec()
        }
        Curve::P384 => {
            let sig: p384::ecdsa::Signature = p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap().sign(tbs);
            sig.to_der().as_bytes().to_vec()
        }
    }
}

pub(super) fn mint(c: Curve, seed: u8, issuer_seed: u8, extensions: &[Vec<u8>]) -> Vec<u8> {
    mint_named(c, seed, issuer_seed, extensions, &tlv(0x30, &[]), &tlv(0x30, &[]))
}

pub(super) fn mint_named(c: Curve, seed: u8, issuer_seed: u8, extensions: &[Vec<u8>], issuer: &[u8], subject: &[u8]) -> Vec<u8> {
    let (sig_oid, curve_oid): (&[u8], &[u8]) = match c {
        Curve::P256 => (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02], &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        Curve::P384 => (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03], &[0x2b, 0x81, 0x04, 0x00, 0x22]),
    };
    let alg = tlv(0x30, &tlv(0x06, sig_oid));
    let validity = tlv(0x30, &[tlv(0x17, b"200101000000Z"), tlv(0x17, b"400101000000Z")].concat());
    let key_alg = tlv(0x30, &[tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), tlv(0x06, curve_oid)].concat());
    let spki = tlv(0x30, &[key_alg, tlv(0x03, &[vec![0], point(c, seed)].concat())].concat());
    let tbs = tlv(
        0x30,
        &[
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[seed]),
            alg.clone(),
            issuer.to_vec(),
            validity,
            subject.to_vec(),
            spki,
            tlv(0xa3, &tlv(0x30, &extensions.concat())),
        ]
        .concat(),
    );
    let bits = tlv(0x03, &[vec![0], sign(c, issuer_seed, &tbs)].concat());
    tlv(0x30, &[tbs, alg, bits].concat())
}

pub(super) fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let crit = if critical { tlv(0x01, &[0xff]) } else { vec![] };
    tlv(0x30, &[tlv(0x06, oid), crit, tlv(0x04, value)].concat())
}
fn ca(path_len: Option<u8>) -> Vec<u8> {
    let pl = path_len.map(|p| tlv(0x02, &[p])).unwrap_or_default();
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[tlv(0x01, &[0xff]), pl].concat()))
}
pub(super) fn not_ca() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x13], true, &tlv(0x30, &[]))
}
fn key_usage(bits: u8) -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0, bits]))
}
fn eku_critical() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x25], true, &tlv(0x30, &tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01])))
}
fn unknown_critical() -> Vec<u8> {
    ext(&[0x2a, 0x03, 0x04], true, &[])
}
pub(super) fn good_ca() -> Vec<Vec<u8>> {
    vec![ca(None), key_usage(0x04)]
}
pub(super) fn good_leaf() -> Vec<Vec<u8>> {
    vec![not_ca()]
}

/// `top_down` lists the extensions from the root down; the result is leaf first. The root signs itself.
pub(super) fn chain(c: Curve, top_down: &[Vec<Vec<u8>>]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = top_down
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let seed = ROOT_SEED + i as u8;
            mint(c, seed, if i == 0 { seed } else { seed - 1 }, e)
        })
        .collect();
    out.reverse();
    out
}

pub(super) fn spki(der: &[u8]) -> String {
    Cert::from_der(der).unwrap().public_key().unwrap().spki_sha256_hex()
}
fn x5c(certs: &[Vec<u8>]) -> X5c {
    certs.iter().map(|d| Some(b64_std(d))).collect()
}
pub(super) fn pem(der: &[u8]) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64_std(der))
}

fn maa_pinned(certs: &[Vec<u8>], pin: &[u8]) -> Option<String> {
    let anchors = MaaAnchors { root_certs_pem: vec![], root_spki_sha256: vec![spki(pin)] };
    verify_x5c_chain(&x5c(certs), &anchors, NOW, 0.0).err()
}
fn maa_external(certs: &[Vec<u8>], root: &[u8]) -> Option<String> {
    let anchors = MaaAnchors { root_certs_pem: vec![pem(root)], root_spki_sha256: vec![] };
    verify_x5c_chain(&x5c(certs), &anchors, NOW, 0.0).err()
}
fn gcp_pinned(certs: &[Vec<u8>], pin: &[u8]) -> Option<String> {
    let anchors = GcpAnchors { trusted_jwks: vec![], trusted_key_spki: vec![spki(pin)], root_certs_pem: vec![] };
    verify_jwk_x5c_chain(&x5c(certs), &anchors, NOW, 0.0)
}
fn gcp_external(certs: &[Vec<u8>], root: &[u8]) -> Option<String> {
    let anchors = GcpAnchors { trusted_jwks: vec![], trusted_key_spki: vec![], root_certs_pem: vec![pem(root)] };
    verify_jwk_x5c_chain(&x5c(certs), &anchors, NOW, 0.0)
}
fn nvidia_pinned(certs: &[Vec<u8>], pin: &[u8]) -> Option<String> {
    let text: String = certs.iter().map(|d| pem(d)).collect();
    verify_device_chain(&text, &[spki(pin)], NOW).err()
}

const LEAF_CA: &str = "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)";
const MID_NOT_CA: &str = "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)";
const MID_NO_SIGN: &str = "issuer certificate at depth 1 keyUsage lacks keyCertSign";
const UNKNOWN_0: &str = "certificate at depth 0 has an unrecognised critical extension 1.2.3.4";
const UNKNOWN_1: &str = "certificate at depth 1 has an unrecognised critical extension 1.2.3.4";

struct Case {
    name: &'static str,
    top_down: Vec<Vec<Vec<u8>>>,
    want: Option<&'static str>,
    /// NVIDIA's `issuer.ca` link check refuses these first (attest-nvidia-spdm.ts:221).
    nvidia_link: Option<&'static str>,
}

fn cases() -> Vec<Case> {
    let case = |name, top_down, want| Case { name, top_down, want, nvidia_link: None };
    let link = Some("device chain cert #1 issues a certificate but is not a CA");
    vec![
        case("a clean chain", vec![good_ca(), good_ca(), good_leaf()], None),
        case("critical EKU is understood here", vec![good_ca(), [good_ca(), vec![eku_critical()]].concat(), vec![not_ca(), eku_critical()]], None),
        case("pathLen 0 over the leaf only", vec![good_ca(), vec![ca(Some(0)), key_usage(0x04)], good_leaf()], None),
        case("leaf CA:TRUE", vec![good_ca(), good_ca(), good_ca()], Some(LEAF_CA)),
        Case { name: "non-CA intermediate", top_down: vec![good_ca(), good_leaf(), good_leaf()], want: Some(MID_NOT_CA), nvidia_link: link },
        Case { name: "keyUsage without keyCertSign", top_down: vec![good_ca(), vec![ca(None), key_usage(0x80)], good_leaf()], want: Some(MID_NO_SIGN), nvidia_link: link },
        case(
            "pathLen exceeded",
            vec![good_ca(), vec![ca(Some(0)), key_usage(0x04)], good_ca(), good_leaf()],
            Some("issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"),
        ),
        case("critical 1.2.3.4 on the leaf", vec![good_ca(), good_ca(), vec![not_ca(), unknown_critical()]], Some(UNKNOWN_0)),
        case("critical 1.2.3.4 on the intermediate", vec![good_ca(), [good_ca(), vec![unknown_critical()]].concat(), good_leaf()], Some(UNKNOWN_1)),
    ]
}

#[test]
fn the_profile_runs_on_the_maa_x5c_chain_under_a_pinned_root() {
    for k in cases() {
        let certs = chain(Curve::P256, &k.top_down);
        let got = maa_pinned(&certs, certs.last().unwrap());
        assert_eq!(got, k.want.map(|m| format!("x5c chain profile: {m}")), "{}", k.name);
    }
}

#[test]
fn the_profile_runs_on_the_gcp_x5c_chain_under_a_pinned_root() {
    for k in cases() {
        let certs = chain(Curve::P256, &k.top_down);
        let got = gcp_pinned(&certs, certs.last().unwrap());
        assert_eq!(got, k.want.map(|m| format!("x5c chain profile: {m}")), "{}", k.name);
    }
}

#[test]
fn the_profile_runs_on_the_nvidia_device_chain_under_a_pinned_root() {
    for k in cases() {
        let certs = chain(Curve::P384, &k.top_down);
        let got = nvidia_pinned(&certs, certs.last().unwrap());
        let want = k.nvidia_link.map(str::to_string).or(k.want.map(|m| format!("device chain profile: {m}")));
        assert_eq!(got, want, "{}", k.name);
    }
}

#[test]
fn the_maa_profile_covers_only_the_slice_up_to_an_in_chain_anchor() {
    // Nothing above the anchor is trusted or read, so a bad certificate there changes nothing (attest-azure-maa.ts:395).
    let bad_top = vec![not_ca(), unknown_critical()];
    let certs = chain(Curve::P256, &[bad_top.clone(), good_ca(), good_leaf()]);
    assert_eq!(maa_pinned(&certs, &certs[1]), None);

    let certs = chain(Curve::P256, &[bad_top, good_ca(), good_ca()]);
    assert_eq!(maa_pinned(&certs, &certs[1]), Some(format!("x5c chain profile: {LEAF_CA}")));

    // A pinned leaf is a chain of one: it has no role relationship, but its critical extensions still count.
    let certs = chain(Curve::P256, &[good_ca(), good_ca()]);
    assert_eq!(maa_pinned(&certs, &certs[0]), None);
    let certs = chain(Curve::P256, &[good_ca(), vec![not_ca(), unknown_critical()]]);
    assert_eq!(maa_pinned(&certs, &certs[0]), Some(format!("x5c chain profile: {UNKNOWN_0}")));
}

#[test]
fn an_external_root_does_not_excuse_a_non_ca_intermediate() {
    let certs = chain(Curve::P256, &[good_ca(), good_leaf(), good_leaf()]);
    let (root, below) = (&certs[2], &certs[..2]);
    let want = Some(format!("x5c chain profile: {MID_NOT_CA}"));
    assert_eq!(maa_external(below, root), want);
    assert_eq!(gcp_external(below, root), want);

    let certs = chain(Curve::P256, &[good_ca(), good_ca(), good_leaf()]);
    assert_eq!(maa_external(&certs[..2], &certs[2]), None);
    assert_eq!(gcp_external(&certs[..2], &certs[2]), None);
}

#[test]
fn each_site_orders_the_profile_against_its_anchor_check_as_the_reference() {
    let other = mint(Curve::P256, OTHER_ROOT_SEED, OTHER_ROOT_SEED, &good_ca());
    let bad = chain(Curve::P256, &[good_ca(), good_leaf(), good_leaf()]);
    let clean = chain(Curve::P256, &[good_ca(), good_ca(), good_leaf()]);

    // MAA checks the anchor first (attest-azure-maa.ts:408-411).
    assert_eq!(maa_external(&bad, &other).as_deref(), Some("x5c chain does not anchor in a configured MAA trust root"));
    assert_eq!(maa_external(&clean, &other).as_deref(), Some("x5c chain does not anchor in a configured MAA trust root"));

    // GCP checks the profile before its pins and roots (attest-gcp-confidential-space.ts:384).
    assert_eq!(gcp_pinned(&bad, &other), Some(format!("x5c chain profile: {MID_NOT_CA}")));
    assert_eq!(gcp_pinned(&clean, &other).as_deref(), Some("x5c chain does not anchor in a configured GCP trust root"));

    // NVIDIA checks the profile before its root checks (attest-nvidia-spdm.ts:224).
    let other = mint(Curve::P384, OTHER_ROOT_SEED, OTHER_ROOT_SEED, &good_ca());
    let bad = chain(Curve::P384, &[good_ca(), [good_ca(), vec![unknown_critical()]].concat(), good_leaf()]);
    let clean = chain(Curve::P384, &[good_ca(), good_ca(), good_leaf()]);
    assert_eq!(nvidia_pinned(&bad, &other), Some(format!("device chain profile: {UNKNOWN_1}")));
    assert_eq!(nvidia_pinned(&clean, &other).as_deref(), Some("chain root is not a pinned NVIDIA root"));
}

#[test]
fn the_helper_reports_roles_first_and_leaves_the_default_set_alone() {
    let both = chain(Curve::P256, &[good_ca(), [good_ca(), vec![unknown_critical()]].concat(), good_ca()]);
    assert_eq!(strict_chain_error(&both).as_deref(), Some(LEAF_CA));

    let mut junk = chain(Curve::P256, &[good_ca(), good_leaf()]);
    junk[0].push(0);
    assert_eq!(strict_chain_error(&junk).as_deref(), Some("certificate extension parse failed: trailing bytes after the certificate"));

    // Only this profile understands EKU; the verifiers using the default set must still refuse it.
    let eku = mint(Curve::P256, 9, 9, &[not_ca(), eku_critical()]);
    assert_eq!(strict_chain_error(&[eku.clone()]), None);
    assert_eq!(unrecognised_critical_extension(&eku, None).unwrap().as_deref(), Some("2.5.29.37"));
}

/// Resolve the signing key of a token whose JWK writes seed `key_seed`'s EC key as x/y beside a genuine x5c chain.
fn gcp_jwk_beside_chain(key_seed: u8, certs: &[Vec<u8>], anchors: &GcpAnchors) -> Result<String, String> {
    let p = point(Curve::P256, key_seed);
    let jwk = serde_json::json!({
        "kid": "k", "kty": "EC", "crv": "P-256", "x": b64url_enc(&p[1..33]), "y": b64url_enc(&p[33..65]),
        "x5c": certs.iter().map(|d| b64_std(d)).collect::<Vec<_>>(),
    });
    let parsed = Jws { alg: "ES256".into(), kid: Some("k".into()), x5c: None, payload: Default::default(), signing_input: vec![], signature: vec![] };
    resolve_trusted_signing_key(&parsed, Some(&serde_json::json!({"keys": [jwk]})), anchors, NOW, 0.0).map(|k| k.spki_sha256_hex())
}

#[test]
fn a_gcp_jwk_key_must_be_the_key_of_its_x5c_leaf() {
    const ATTACKER: u8 = 77;
    let certs = chain(Curve::P256, &[good_ca(), good_leaf()]);
    let (leaf, root) = (&certs[0], &certs[1]);
    let pinned = GcpAnchors { trusted_jwks: vec![], trusted_key_spki: vec![spki(root)], root_certs_pem: vec![] };
    let rooted = GcpAnchors { trusted_jwks: vec![], trusted_key_spki: vec![], root_certs_pem: vec![pem(root)] };
    for anchors in [&pinned, &rooted] {
        // The forgery: the attacker's key, a genuine public chain.
        assert_eq!(
            gcp_jwk_beside_chain(ATTACKER, &certs, anchors),
            Err("signing key not trusted: the JWK key is not the key of its x5c leaf".to_string())
        );
        // The honest leaf key written as x/y beside its own chain (leaf seed: ROOT_SEED + 1).
        assert_eq!(gcp_jwk_beside_chain(ROOT_SEED + 1, &certs, anchors), Ok(spki(leaf)));
    }
    // A broken chain still reports the chain, ahead of the key comparison.
    let unanchored = GcpAnchors { trusted_jwks: vec![], trusted_key_spki: vec!["00".into()], root_certs_pem: vec![] };
    assert_eq!(
        gcp_jwk_beside_chain(ATTACKER, &certs, &unanchored),
        Err("signing key not trusted: x5c chain does not anchor in a configured GCP trust root".to_string())
    );
}

#[test]
fn a_delegated_responder_needs_every_part_of_check_issued() {
    let cn = |n: &[u8]| {
        let atv = tlv(0x30, &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, n)].concat());
        tlv(0x30, &tlv(0x31, &atv))
    };
    let (ca_name, other) = (cn(b"ca"), cn(b"other"));
    let ski = |id: &[u8]| ext(&[0x55, 0x1d, 0x0e], false, &tlv(0x04, id));
    let aki = |id: &[u8]| ext(&[0x55, 0x1d, 0x23], false, &tlv(0x30, &tlv(0x80, id)));
    let cert = |d: Vec<u8>| Cert::from_der(&d).unwrap();
    let issuer = |exts: &[Vec<u8>]| cert(mint_named(Curve::P256, 1, 1, exts, &ca_name, &ca_name));
    let responder = |seed: u8, exts: &[Vec<u8>], iss: &[u8]| cert(mint_named(Curve::P256, 2, seed, exts, iss, &cn(b"r")));
    let ca = issuer(&[ski(b"id1"), key_usage(0x04)]);

    assert!(delegated_issued_by(&responder(1, &[aki(b"id1")], &ca_name), &ca), "matching AKID");
    assert!(delegated_issued_by(&responder(1, &[not_ca()], &ca_name), &ca), "no AKID");
    assert!(delegated_issued_by(&responder(1, &[aki(b"id1")], &ca_name), &issuer(&[ski(b"id1")])), "keyUsage absent");
    assert!(!delegated_issued_by(&responder(1, &[aki(b"id2")], &ca_name), &ca), "AKID differs from the SKID");
    assert!(!delegated_issued_by(&responder(1, &[not_ca()], &other), &ca), "issuer name differs");
    assert!(!delegated_issued_by(&responder(9, &[not_ca()], &ca_name), &ca), "signed by another key");
    assert!(!delegated_issued_by(&responder(1, &[not_ca()], &ca_name), &issuer(&[key_usage(0x80)])), "keyUsage without keyCertSign");
    // A keyUsage too short to carry the bit is not keyCertSign.
    let short = ext(&[0x55, 0x1d, 0x0f], true, &tlv(0x03, &[0x00]));
    assert!(!delegated_issued_by(&responder(1, &[not_ca()], &ca_name), &issuer(&[short])), "empty keyUsage");
    // X509_check_akid's [1] and [2], through both callers. `mint_named` gives the issuer serial [1] and issuer name `ca_name`.
    let aki_of = |members: &[Vec<u8>]| ext(&[0x55, 0x1d, 0x23], false, &tlv(0x30, &members.concat()));
    let (key_id, serial) = (tlv(0x80, b"id1"), |b: u8| tlv(0x82, &[b]));
    let dir = |n: &[u8]| tlv(0xa1, &tlv(0xa4, n));
    let linked = |exts: &[Vec<u8>]| {
        let r = responder(1, exts, &ca_name);
        let (a, b) = (delegated_issued_by(&r, &ca), crate::sigstore::key_ids_match(&r, &ca));
        assert_eq!(a, b, "the same check on both paths");
        a
    };
    assert!(linked(&[aki_of(&[key_id.clone(), dir(&ca_name), serial(1)])]), "serial and directory name match");
    assert!(!linked(&[aki_of(&[key_id.clone(), dir(&ca_name), serial(2)])]), "AKID serial differs");
    assert!(!linked(&[aki_of(&[key_id, dir(&other), serial(1)])]), "AKID directory name differs");
}

// ---- OCSP SingleResponse strictness: every response below is correctly signed by the issuer

const OCSP_THIS: &[u8] = b"20270114000000Z"; // NOW is 2027-01-15
const OCSP_FUTURE: &[u8] = b"20270120000000Z";
const OCSP_PAST: &[u8] = b"20270114120000Z";

fn ocsp_gt(t: &[u8]) -> Vec<u8> {
    tlv(0x18, t)
}

/// A SingleResponse for `subject` (issued by `issuer`) with `status` and these elements after thisUpdate.
fn ocsp_single(subject: &Cert, issuer: &Cert, status: &[u8], rest: &[Vec<u8>]) -> Vec<u8> {
    let alg = tlv(0x30, &tlv(0x06, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])); // sha-256
    let id = [alg, tlv(0x04, &digest(Hash::Sha256, &issuer.subject)), tlv(0x04, &digest(Hash::Sha256, &key_bits(&issuer.spki))), tlv(0x02, &subject.serial)].concat();
    tlv(0x30, &[tlv(0x30, &id), status.to_vec(), ocsp_gt(OCSP_THIS), rest.concat()].concat())
}

fn ocsp_response(issuer: &Cert, issuer_seed: u8, singles: &[Vec<u8>]) -> Vec<u8> {
    let rid = tlv(0xa2, &tlv(0x04, &sha1(&key_bits(&issuer.spki))));
    let tbs = tlv(0x30, &[rid, ocsp_gt(OCSP_THIS), tlv(0x30, &singles.concat())].concat());
    let alg = tlv(0x30, &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])); // ecdsa-with-SHA256
    let sig = tlv(0x03, &[vec![0], sign(Curve::P256, issuer_seed, &tbs)].concat());
    let basic = tlv(0x30, &[tbs, alg, sig].concat());
    let oid = tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
    let rb = tlv(0x30, &[oid, tlv(0x04, &basic)].concat());
    tlv(0x30, &[tlv(0x0a, &[0]), tlv(0xa0, &rb)].concat())
}

#[test]
fn a_single_response_holds_only_next_update_then_extensions() {
    let issuer = Cert::from_der(&mint(Curve::P256, 1, 1, &good_ca())).unwrap();
    let leaf = Cert::from_der(&mint(Curve::P256, 2, 1, &good_leaf())).unwrap();
    let other = Cert::from_der(&mint(Curve::P256, 3, 1, &good_leaf())).unwrap();
    let good = tlv(0x80, &[]);
    let next = |t: &[u8]| tlv(0xa0, &ocsp_gt(t));
    let exts = tlv(0xa1, &tlv(0x30, &[]));
    let run = |rest: &[Vec<u8>]| verify_ocsp_response(&ocsp_response(&issuer, 1, &[ocsp_single(&leaf, &issuer, &good, rest)]), &leaf, &issuer, &[], NOW).map(|_| ());
    let bad = Err("OCSP response rejected: Object's schema was not verified against input data for BasicOCSPResponse".to_string());

    assert_eq!(run(&[]), Ok(()));
    assert_eq!(run(&[next(OCSP_FUTURE)]), Ok(()));
    assert_eq!(run(&[next(OCSP_FUTURE), exts.clone()]), Ok(()));
    assert_eq!(run(&[exts.clone()]), Ok(()));
    assert_eq!(run(&[next(OCSP_PAST)]), Err("response is stale (past nextUpdate)".to_string()));

    // A past nextUpdate under an unknown tag was read as no nextUpdate at all.
    assert_eq!(run(&[tlv(0xa2, &ocsp_gt(OCSP_PAST))]), bad);
    assert_eq!(run(&[exts.clone(), next(OCSP_PAST)]), bad, "wrong order");
    assert_eq!(run(&[next(OCSP_FUTURE), next(OCSP_FUTURE)]), bad);
    assert_eq!(run(&[next(OCSP_FUTURE), exts.clone(), exts.clone()]), bad);
    assert_eq!(run(&[next(OCSP_FUTURE), tlv(0xa2, &[])]), bad);

    // The nextUpdate wrapper holds exactly one GeneralizedTime.
    assert_eq!(run(&[tlv(0xa0, &[])]), bad);
    assert_eq!(run(&[tlv(0xa0, &[ocsp_gt(OCSP_FUTURE), ocsp_gt(OCSP_PAST)].concat())]), bad);
    assert_eq!(run(&[tlv(0xa0, &tlv(0x17, b"270120000000Z"))]), bad);
    assert!(run(&[tlv(0xa0, &[0x18, 0x7f])]).is_err(), "child overruns its wrapper");

    // Every SingleResponse is held to this, not only the matching one.
    let singles = [ocsp_single(&leaf, &issuer, &good, &[]), ocsp_single(&other, &issuer, &good, &[tlv(0xa2, &[])])];
    assert_eq!(verify_ocsp_response(&ocsp_response(&issuer, 1, &singles), &leaf, &issuer, &[], NOW).map(|_| ()), bad);
    let singles = [ocsp_single(&leaf, &issuer, &good, &[]), ocsp_single(&other, &issuer, &good, &[tlv(0xa0, &[])])];
    assert_eq!(verify_ocsp_response(&ocsp_response(&issuer, 1, &singles), &leaf, &issuer, &[], NOW).map(|_| ()), bad);

    // Constructed certStatus tags are not good or unknown, and a primitive [1] is not revoked.
    for tag in [0xa0, 0xa2, 0x81] {
        let r = ocsp_response(&issuer, 1, &[ocsp_single(&leaf, &issuer, &tlv(tag, &[]), &[])]);
        assert_eq!(verify_ocsp_response(&r, &leaf, &issuer, &[], NOW).map(|_| ()), bad, "{tag:#x}");
    }
}

/// A compact ES256 JWS signed by `seed` (the shape the MAA and Confidential Space readers take).
pub(super) fn es256_token(seed: u8, header: &serde_json::Value, payload: &serde_json::Value) -> String {
    let input = format!("{}.{}", b64url_enc(header.to_string().as_bytes()), b64url_enc(payload.to_string().as_bytes()));
    let sig: p256::ecdsa::Signature = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap().sign(input.as_bytes());
    format!("{input}.{}", b64url_enc(&sig.to_bytes()))
}
