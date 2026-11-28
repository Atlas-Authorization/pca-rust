//! Kill tests for the MAA reader: the `x5c` source, the anchor error wrapper and the time window with its skew
//! (attest-azure-maa.ts:586-601, :416, :702-709). Tokens are really signed by the leaf of a chain pinned at its root.

use super::{verify_x5c_chain, MaaAnchors, MaaVerifier, X5c};
use crate::attest::strict_chain_tests::{chain, es256_token, good_ca, good_leaf, spki, Curve, NOW};
use crate::attest::util::b64_std;
use crate::attest::{AttResult, Binding};
use serde_json::{json, Value};

const LEAF_SEED: u8 = 2; // chain() seeds the root 1, the next certificate 2
const NOW_SEC: i64 = 1_800_000_000;
/// The first check after the time window: the token got through it.
const PAST_TIMES: &str = "unexpected x-ms-attestation-type 'undefined' (expected sevsnpvm | tdxvm)";
const ISS: &str = "https://maa.example";

fn certs() -> Vec<Vec<u8>> {
    chain(Curve::P256, &[good_ca(), good_leaf()])
}
fn x5c_strings() -> Vec<String> {
    certs().iter().map(|d| b64_std(d)).collect()
}

fn reason(r: AttResult) -> String {
    if r.ok {
        "ok".to_string()
    } else {
        r.reason.unwrap()
    }
}

fn run(header: Value, payload: Value, jwks: Option<Value>, skew_ms: u64) -> String {
    let cfg = json!({
        "trustedIssuers": [ISS],
        "trustAnchors": { "rootSpkiSha256": [spki(&certs()[1])] },
        "policy": { "tdxMrtds": ["00"] },
        "clockSkewMs": skew_ms,
    });
    let v = MaaVerifier::from_config(cfg.as_object().unwrap()).unwrap();
    let mut ev = json!({ "token": es256_token(LEAF_SEED, &header, &payload) });
    if let Some(j) = jwks {
        ev["jwks"] = j;
    }
    let binding = Binding { holder_pub: "h".into(), grant_ref: "g".into(), epoch: 1.0, nonce: "n".into() };
    reason(v.verify(Some(&ev), NOW as i64, Some(&binding)))
}

fn with_x5c() -> Value {
    json!({ "alg": "ES256", "x5c": x5c_strings() })
}

fn claims(extra: Value) -> Value {
    let mut p = json!({ "iss": ISS, "exp": NOW_SEC + 100 });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    p
}

#[test]
fn the_time_window_with_skew_rounds_up_to_whole_seconds() {
    const SKEW: u64 = 1500; // Math.ceil(1500 / 1000) = 2 seconds
    for (name, extra, skew, want) in [
        ("exp at now - skew", json!({ "exp": NOW_SEC - 2 }), SKEW, PAST_TIMES),
        ("exp 1 s before", json!({ "exp": NOW_SEC - 3 }), SKEW, "MAA token expired"),
        ("exp just gone, no skew", json!({ "exp": NOW_SEC - 1 }), 0, "MAA token expired"),
        ("nbf at now + skew", json!({ "nbf": NOW_SEC + 2 }), SKEW, PAST_TIMES),
        ("nbf 1 s after", json!({ "nbf": NOW_SEC + 3 }), SKEW, "MAA token not yet valid (nbf)"),
        ("iat at now + skew", json!({ "iat": NOW_SEC + 2 }), SKEW, PAST_TIMES),
        ("iat 1 s after", json!({ "iat": NOW_SEC + 3 }), SKEW, "MAA token issued in the future (iat)"),
        ("iat at now, no skew", json!({ "iat": NOW_SEC }), 0, PAST_TIMES),
        ("iat 1 s after, no skew", json!({ "iat": NOW_SEC + 1 }), 0, "MAA token issued in the future (iat)"),
    ] {
        assert_eq!(run(with_x5c(), claims(extra), None, skew), want, "{name}");
    }
}

#[test]
fn the_signing_chain_comes_from_the_jwks_or_the_header() {
    let jwks = || json!({ "keys": [{ "x5c": x5c_strings() }] });
    // An empty kid is no kid: the sole published key signs (attest-azure-maa.ts:588).
    assert_eq!(run(json!({ "alg": "ES256", "kid": "" }), claims(json!({})), Some(jwks()), 0), PAST_TIMES);
    assert_eq!(run(json!({ "alg": "ES256", "kid": "z" }), claims(json!({})), Some(jwks()), 0), "no JWKS key matches the token kid 'z' (untrusted signer)");
    // An empty header x5c is no x5c (attest-azure-maa.ts:600).
    assert_eq!(run(json!({ "alg": "ES256", "x5c": [] }), claims(json!({})), None, 0), "no signing x5c available (no JWKS and no header x5c)");
    assert_eq!(run(with_x5c(), claims(json!({})), None, 0), PAST_TIMES);
}

#[test]
fn an_unreadable_root_is_reported_inside_the_wrapper() {
    let x5c: X5c = x5c_strings().into_iter().map(Some).collect();
    let anchors = MaaAnchors { root_certs_pem: vec!["junk".to_string()], root_spki_sha256: vec![] };
    // attest-azure-maa.ts:416 wraps what `new X509Certificate('junk')` throws; that text is OpenSSL's and varies with its version.
    let got = verify_x5c_chain(&x5c, &anchors, NOW, 0.0).err().unwrap();
    assert!(got.starts_with("x5c chain verification error (fail closed): error:"), "{got}");
}
