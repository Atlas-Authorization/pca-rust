//! Kill tests for the Confidential Space reader (attest-gcp-confidential-space.ts): `keyFromJwk`, the chain and anchor checks, the
//! key pick, the time window with its skew and the claim gates. Tokens are really signed; every token is valid but for one claim.

use super::{key_from_jwk, pad_to, resolve_trusted_signing_key, tee_type_of_hwmodel, verify_jwk_x5c_chain, GcpAnchors, GcpVerifier};
use crate::attest::jws::Jws;
use crate::attest::strict_chain_tests::{chain, es256_token, good_ca, good_leaf, mint, point, spki, Curve, NOW};
use crate::attest::util::{b64_std, b64url_enc, hex_lower};
use crate::attest::x509::{EcCurve, PubKey};
use crate::attest::{attestation_binding, Binding};
use serde_json::{json, Value};

const SIGNER: u8 = 40;
const OTHER: u8 = 41;
const NOW_SEC: i64 = 1_800_000_000;
const IMAGE: &str = "sha256:aa";

// A P-521 key from node:crypto (this crate has no P-521 validity check, the reference's createPublicKey does).
const P521_X: &str = "AFqttfPQejCaOQZ14KZ-xEEJ-C2S9s3OEhxBLXBXgR7eipx7WG0Q33iHeAxjyAUXPWplpUK8nDhs2VdHjzeqWJAE";
const P521_Y: &str = "AUyfoHLpKfHplvfYGwM3D6cV5nc709kOgNOOCeJQXVKI3I7axBEFPuZzvSzWWaW3WYTGgSRYbDYzjHsj1KChjJS9";

fn jwk_of(curve: Curve, crv: &str, seed: u8) -> Value {
    let p = point(curve, seed);
    let n = (p.len() - 1) / 2;
    json!({ "kty": "EC", "crv": crv, "x": b64url_enc(&p[1..1 + n]), "y": b64url_enc(&p[1 + n..]) })
}
fn jwk(seed: u8) -> Value {
    jwk_of(Curve::P256, "P-256", seed)
}
fn key_of(v: &Value) -> Result<PubKey, String> {
    key_from_jwk(v.as_object().unwrap())
}

fn binding() -> Binding {
    Binding { holder_pub: "h".into(), grant_ref: "g".into(), epoch: 1.0, nonce: "n".into() }
}

fn claims(extra: Value) -> Value {
    let mut p = json!({
        "iss": "https://i",
        "exp": NOW_SEC + 100,
        "submods": { "confidential_space": {}, "container": { "image_digest": IMAGE } },
        "swname": "CONFIDENTIAL_SPACE",
        "hwmodel": "GCP_AMD_SEV_SNP",
        "dbgstat": "disabled-since-boot",
        "eat_nonce": hex_lower(&attestation_binding(&binding()).unwrap()),
    });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    p
}

fn run(header: Value, payload: Value, policy: Value, skew_ms: u64) -> String {
    let mut pol = json!({ "imageDigests": [IMAGE] });
    for (k, v) in policy.as_object().unwrap() {
        pol[k] = v.clone();
    }
    let cfg = json!({ "trustedIssuers": ["https://i"], "trustAnchors": { "trustedJwks": { "keys": [jwk(SIGNER)] } }, "policy": pol, "clockSkewMs": skew_ms });
    let v = GcpVerifier::from_config(cfg.as_object().unwrap()).unwrap();
    let ev = json!({ "token": es256_token(SIGNER, &header, &payload) });
    let r = v.verify(Some(&ev), NOW as i64, Some(&binding()));
    if r.ok {
        "ok".to_string()
    } else {
        r.reason.unwrap()
    }
}

fn es256() -> Value {
    json!({ "alg": "ES256" })
}

#[test]
fn the_time_window_with_skew_rounds_up_to_whole_seconds() {
    const SKEW: u64 = 1500; // Math.ceil(1500 / 1000) = 2 seconds
    for (name, extra, skew, want) in [
        ("exp at now - skew", json!({ "exp": NOW_SEC - 2 }), SKEW, "ok"),
        ("exp 1 s before", json!({ "exp": NOW_SEC - 3 }), SKEW, "Confidential Space token expired"),
        ("nbf at now + skew", json!({ "nbf": NOW_SEC + 2 }), SKEW, "ok"),
        ("nbf 1 s after", json!({ "nbf": NOW_SEC + 3 }), SKEW, "Confidential Space token not yet valid (nbf)"),
        ("iat at now + skew", json!({ "iat": NOW_SEC + 2 }), SKEW, "ok"),
        ("iat 1 s after", json!({ "iat": NOW_SEC + 3 }), SKEW, "Confidential Space token issued in the future (iat)"),
        ("nbf at now, no skew", json!({ "nbf": NOW_SEC }), 0, "ok"),
        ("nbf 1 s after, no skew", json!({ "nbf": NOW_SEC + 1 }), 0, "Confidential Space token not yet valid (nbf)"),
        ("iat at now, no skew", json!({ "iat": NOW_SEC }), 0, "ok"),
        ("iat 1 s after, no skew", json!({ "iat": NOW_SEC + 1 }), 0, "Confidential Space token issued in the future (iat)"),
    ] {
        assert_eq!(run(es256(), claims(extra), json!({}), skew), want, "{name}");
    }
}

#[test]
fn empty_claims_are_absent_claims() {
    let not_allowed = "swversion not in policy allowlist";
    let versions = |list: Value| json!({ "allowedSwVersions": list });
    assert_eq!(run(es256(), claims(json!({ "swversion": "" })), versions(json!([""])), 0), not_allowed);
    assert_eq!(run(es256(), claims(json!({ "swversion": "v1" })), versions(json!(["v1"])), 0), "ok");
    assert_eq!(run(es256(), claims(json!({ "swversion": ["v0", "v1"] })), versions(json!(["v1"])), 0), "ok");
    assert_eq!(run(es256(), claims(json!({ "swversion": "v2" })), versions(json!(["v1"])), 0), not_allowed);

    assert_eq!(run(es256(), claims(json!({ "hwmodel": "" })), json!({}), 0), "token carries no hwmodel claim");
    assert_eq!(
        run(es256(), claims(json!({ "submods": { "confidential_space": {}, "container": { "image_digest": "" } } })), json!({}), 0),
        "token carries no submods.container.image_digest to measure the workload"
    );
}

#[test]
fn the_key_is_picked_by_a_non_empty_kid_else_it_must_be_the_sole_key() {
    assert_eq!(run(json!({ "alg": "ES256", "kid": "" }), claims(json!({})), json!({}), 0), "ok");
    assert_eq!(
        run(json!({ "alg": "ES256", "kid": "z" }), claims(json!({})), json!({}), 0),
        "Confidential Space signing key invalid: no JWKS key matches the token kid 'z' (untrusted signer)"
    );
}

#[test]
fn hwmodels_map_as_the_reference() {
    for (m, want) in [
        ("GCP_AMD_SEV", Some("sev-snp")),
        ("GCP_AMD_SEV_SNP", Some("sev-snp")),
        ("GCP_AMD_SEV_ES", Some("sev-snp")),
        ("GCP_AMD_SEV_LATER", Some("sev-snp")),
        ("gcp_amd_sev", Some("sev-snp")),
        ("GCP_INTEL_TDX", Some("tdx")),
        ("gcp_intel_tdx_later", Some("tdx")),
        ("GCP_AMD", None),
        ("", None),
    ] {
        assert_eq!(tee_type_of_hwmodel(m), want, "{m}");
    }
}

#[test]
fn pad_to_keeps_the_value_and_refuses_what_does_not_fit() {
    assert_eq!(pad_to(&[1, 2], 4), Some(vec![0, 0, 1, 2]));
    assert_eq!(pad_to(&[1, 2, 3, 4], 4), Some(vec![1, 2, 3, 4]));
    assert_eq!(pad_to(&[0, 0, 1], 2), Some(vec![0, 1]));
    assert_eq!(pad_to(&[1, 2, 3], 2), None);
}

#[test]
fn key_from_jwk_reads_each_form() {
    let usable = "JWKS key is not a usable public key: ";
    let refused = |v: Value| key_of(&v).err().unwrap_or_default();
    assert!(refused(json!({ "n": "", "e": "AQAB" })).starts_with(usable));
    assert!(refused(json!({ "n": "AQAB", "e": "" })).starts_with(usable));
    assert!(matches!(key_of(&json!({ "n": "AQAB", "e": "AQAB" })), Ok(PubKey::Rsa { .. })));

    let ec = |v: Value, curve: EcCurve, seed: Option<Vec<u8>>| match key_of(&v) {
        Ok(PubKey::Ec { curve: c, point: p }) => assert!(c == curve && seed.map_or(p.len() == 133, |s| s == p), "{v}"),
        other => panic!("{v}: {other:?}"),
    };
    ec(jwk(SIGNER), EcCurve::P256, Some(point(Curve::P256, SIGNER)));
    ec(jwk_of(Curve::P384, "P-384", SIGNER), EcCurve::P384, Some(point(Curve::P384, SIGNER)));
    ec(json!({ "kty": "EC", "crv": "P-521", "x": P521_X, "y": P521_Y }), EcCurve::P521, None);

    assert!(refused(json!({ "kty": "EC", "crv": "secp256k1", "x": "AQ", "y": "AQ" })).starts_with(usable));
    // Off the curve: the point check runs on P-256 and P-384.
    assert!(refused(json!({ "kty": "EC", "crv": "P-256", "x": "AQ", "y": "AQ" })).starts_with(usable));
    assert!(refused(json!({ "kty": "EC", "crv": "P-384", "x": "AQ", "y": "AQ" })).starts_with(usable));
    assert_eq!(refused(json!({ "kty": "OKP" })), "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate");
}

fn pinned(der: &[u8]) -> GcpAnchors {
    GcpAnchors { trusted_jwks: vec![], trusted_key_spki: vec![spki(der)], root_certs_pem: vec![] }
}

#[test]
fn the_chain_checks_report_their_reason() {
    let clean = chain(Curve::P256, &[good_ca(), good_leaf()]);
    let anchors = pinned(&clean[1]);
    let run = |x5c: Vec<Option<String>>| verify_jwk_x5c_chain(&x5c, &anchors, NOW, 0.0);
    fn b64(d: &[Vec<u8>]) -> Vec<Option<String>> {
        d.iter().map(|c| Some(b64_std(c))).collect()
    }
    assert_eq!(run(vec![]).as_deref(), Some("empty x5c certificate chain"));
    assert_eq!(run(vec![Some(String::new())]).as_deref(), Some("empty x5c entry at index 0"));
    assert_eq!(run(vec![None]).as_deref(), Some("empty x5c entry at index 0"));
    assert_eq!(run(b64(&clean)), None);
    let unrelated = [mint(Curve::P256, 10, 11, &good_leaf()), clean[1].clone()];
    assert_eq!(run(b64(&unrelated)).as_deref(), Some("x5c link 0 is not signed by the certificate above it"));
}

#[test]
fn a_chain_is_walked_only_when_a_root_or_pin_is_configured() {
    let certs = chain(Curve::P256, &[good_ca(), good_leaf()]);
    let evidence = json!({ "keys": [{ "kid": "k", "x5c": certs.iter().map(|d| b64_std(d)).collect::<Vec<_>>() }] });
    let parsed = Jws { alg: "ES256".into(), kid: Some("k".into()), x5c: None, payload: Default::default(), signing_input: vec![], signature: vec![] };
    let mut other = jwk(OTHER);
    other["kid"] = json!("other");
    let only_jwks = GcpAnchors { trusted_jwks: vec![other], trusted_key_spki: vec![], root_certs_pem: vec![] };
    assert_eq!(
        resolve_trusted_signing_key(&parsed, Some(&evidence), &only_jwks, NOW, 0.0).map(|k| k.spki_sha256_hex()),
        Err("signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)".to_string())
    );
    assert_eq!(resolve_trusted_signing_key(&parsed, Some(&evidence), &pinned(&certs[1]), NOW, 0.0).map(|k| k.spki_sha256_hex()), Ok(spki(&certs[0])));
}
