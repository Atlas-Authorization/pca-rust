//! k05b group g6: kills for the unledgered survivors of the full cargo-mutants run 42434682442 in attest/der.rs, attest/snp.rs,
//! attest/gcp.rs, intent_acc.rs, intent_session.rs, mesh.rs and middleware.rs. Every expected string is copied from src (the
//! TypeScript reference words them the same way).
#![allow(dead_code)]

mod common;

use atlas_pca::attest::der::{der_validity_ms, parse_tbs_extensions, read_cert_role_info, tbs_of_certificate};
use atlas_pca::attest::gcp::GcpVerifier;
use atlas_pca::attest::snp::{check_vcek_report_binding, k05b_verify_amd_cert_chain, parse_report};
use atlas_pca::attest::x509::{der_wrap, pem_to_der};
use atlas_pca::k05b_g6_seam as seam;
use atlas_pca::{session_root_shape_error, verify_mesh_proof};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Map, Value};

const NOW: i64 = 1_800_000_000_000;

fn b32(n: u8) -> String {
    URL_SAFE_NO_PAD.encode([n; 32])
}

// ---- DER fixtures -------------------------------------------------------------------------------------------------

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    der_wrap(tag, body)
}
fn ext(oid: &[u8], critical: Option<u8>, value: &[u8]) -> Vec<u8> {
    let mut body = tlv(0x06, oid);
    if let Some(c) = critical {
        body.extend(tlv(0x01, &[c]));
    }
    body.extend(tlv(0x04, value));
    tlv(0x30, &body)
}
fn exts(list: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &list.concat())
}
/// A minimal tbsCertificate carrying the given `[3]` extensions block bodies.
fn tbs_with(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut body = tlv(0x02, &[1]);
    for b in blocks {
        body.extend(tlv(0xa3, b));
    }
    tlv(0x30, &body)
}
const BC: [u8; 3] = [0x55, 0x1d, 0x13];

#[test]
fn der_readers_refuse_a_wrong_outer_tag_before_reading_on() {
    // an element whose tag is not SEQUENCE but whose (empty) body would otherwise parse as "no elements"
    assert_eq!(read_cert_role_info(&[0x30, 0x02, 0x04, 0x00]).unwrap_err(), "certificate has no tbsCertificate");
    assert_eq!(parse_tbs_extensions(&[0x04, 0x00]).unwrap_err(), "tbsCertificate is not a SEQUENCE");
    assert_eq!(tbs_of_certificate(&[0x31, 0x02, 0x30, 0x00]).unwrap_err(), "certificate is not a DER SEQUENCE");
    assert_eq!(tbs_of_certificate(&[0x30, 0x02, 0x04, 0x00]).unwrap_err(), "certificate has no tbsCertificate");
    assert_eq!(tbs_of_certificate(&[0x30, 0x02, 0x30, 0x00]).unwrap(), vec![0x30, 0x00]);
}

#[test]
fn an_extension_that_is_not_a_sequence_is_refused_even_when_its_body_is_well_formed() {
    let body = [tlv(0x06, &BC), tlv(0x04, &[])].concat();
    let odd = tlv(0x31, &body);
    assert_eq!(parse_tbs_extensions(&tbs_with(&[exts(&[odd])])).unwrap_err(), "extension is not a SEQUENCE");
    // the same body under SEQUENCE parses
    let ok = parse_tbs_extensions(&tbs_with(&[exts(&[tlv(0x30, &body)])])).unwrap();
    assert_eq!(ok.len(), 1);
}

#[test]
fn an_oid_arc_wider_than_120_bits_is_malformed() {
    // 18 continuation bytes of 0x7f ones (126 bits) then the final byte: the 19th byte finds more than 120 bits accumulated
    let mut wide = vec![0xffu8; 18];
    wide.push(0x7f);
    assert_eq!(parse_tbs_extensions(&tbs_with(&[exts(&[ext(&wide, None, &[])])])).unwrap_err(), "extension OID is malformed");
    // 17 continuation bytes (119 bits) still decode
    let mut fits = vec![0xffu8; 17];
    fits.push(0x7f);
    assert_eq!(parse_tbs_extensions(&tbs_with(&[exts(&[ext(&fits, None, &[])])])).unwrap().len(), 1);
}

/// A certificate skeleton `{ tbs { serial, sigAlg, issuer, validity { notBefore, notAfter, extra } } }` with settable tags.
fn vcert(outer: u8, tbs: u8, serial: u8, sig: u8, issuer: u8, extra: &[u8]) -> Vec<u8> {
    let mut validity = tlv(0x17, b"200101000000Z");
    validity.extend(tlv(0x17, b"300101000000Z"));
    validity.extend_from_slice(extra);
    let mut t = tlv(serial, &[1]);
    t.extend(tlv(sig, &[]));
    t.extend(tlv(issuer, &[]));
    t.extend(tlv(0x30, &validity));
    tlv(outer, &tlv(tbs, &t))
}

#[test]
fn der_validity_is_read_only_from_a_wellformed_skeleton() {
    let ok = (Some(1_577_836_800_000i64), Some(1_893_456_000_000i64));
    assert_eq!(der_validity_ms(&vcert(0x30, 0x30, 0x02, 0x30, 0x30, &[])), ok);
    let none = (None, None);
    assert_eq!(der_validity_ms(&vcert(0x31, 0x30, 0x02, 0x30, 0x30, &[])), none, "outer is not a SEQUENCE");
    assert_eq!(der_validity_ms(&vcert(0x30, 0x31, 0x02, 0x30, 0x30, &[])), none, "tbs is not a SEQUENCE");
    assert_eq!(der_validity_ms(&vcert(0x30, 0x30, 0x04, 0x30, 0x30, &[])), none, "serial is not an INTEGER");
    assert_eq!(der_validity_ms(&vcert(0x30, 0x30, 0x02, 0x31, 0x30, &[])), none, "signature algorithm is not a SEQUENCE");
    assert_eq!(der_validity_ms(&vcert(0x30, 0x30, 0x02, 0x30, 0x31, &[])), none, "issuer is not a SEQUENCE");
    assert_eq!(der_validity_ms(&vcert(0x30, 0x30, 0x02, 0x30, 0x30, &tlv(0x05, &[]))), none, "validity holds a third element");
}

// ---- AMD SEV-SNP ---------------------------------------------------------------------------------------------------

const HWID: [u8; 9] = [0x2b, 6, 1, 4, 1, 0x9c, 0x78, 1, 4];
fn spl_oid(last: u8) -> [u8; 10] {
    [0x2b, 6, 1, 4, 1, 0x9c, 0x78, 1, 3, last]
}
/// A VCEK tbsCertificate whose hwID and SPL extensions match an all-zero reported TCB and chip id 0xab * 64.
fn vcek_tbs(hw_critical: Option<u8>, bootloader_critical: Option<u8>) -> Vec<u8> {
    let mut list = vec![ext(&HWID, hw_critical, &[0xab; 64])];
    for (last, crit) in [(1u8, bootloader_critical), (2, None), (3, None), (8, None)] {
        list.push(ext(&spl_oid(last), crit, &[2, 1, 0]));
    }
    tbs_with(&[exts(&list)])
}

#[test]
fn a_critical_amd_extension_is_refused() {
    let mut raw = vec![0u8; 816];
    raw[0x1a0..0x1e0].fill(0xab);
    let report = parse_report(&raw).unwrap();
    // the OID encodings used above are the AMD ones
    let table = parse_tbs_extensions(&vcek_tbs(None, None)).unwrap();
    assert_eq!(table[0].oid, "1.3.6.1.4.1.3704.1.4");
    assert_eq!(table[1].oid, "1.3.6.1.4.1.3704.1.3.1");
    assert_eq!(check_vcek_report_binding(&vcek_tbs(None, None), &report), None);
    assert_eq!(
        check_vcek_report_binding(&vcek_tbs(Some(0xff), None), &report),
        Some("VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)".to_string())
    );
    assert_eq!(
        check_vcek_report_binding(&vcek_tbs(None, Some(0xff)), &report),
        Some("VCEK bootloader SPL extension is marked critical (the AMD profile is non-critical)".to_string())
    );
}

#[test]
fn the_amd_chain_needs_a_finite_verifier_clock() {
    let want = "nowMs (verifier clock) is required for the AMD chain validity check".to_string();
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(k05b_verify_amd_cert_chain(&[], "", "", bad, None), Err(want.clone()), "{bad}");
    }
    assert_ne!(k05b_verify_amd_cert_chain(&[], "", "", 0.0, None), Err(want));
}

// ---- GCP Confidential Space ---------------------------------------------------------------------------------------

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

/// What the Confidential Space verifier says of a token whose `x5c` is the (self-signed, P-384) test root, with `anchor_pem` the
/// only configured root.
fn gcp_reason(anchor_pem: &str) -> String {
    let cfg = json!({
        "trustedIssuers": ["https://confidentialcomputing.googleapis.com"],
        "trustAnchors": {"rootCertsPem": [anchor_pem]},
        "policy": {"imageDigests": ["sha256:00"]}
    });
    let v = GcpVerifier::from_config(cfg.as_object().unwrap()).unwrap();
    let der = pem_to_der(ROOT_PEM).unwrap();
    let header = json!({"alg": "ES256", "x5c": [STANDARD.encode(&der)]});
    let payload = json!({"iss": "https://confidentialcomputing.googleapis.com"});
    let token = format!("{}.{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(payload.to_string()), URL_SAFE_NO_PAD.encode([7u8; 64]));
    v.verify(Some(&json!({ "token": token })), NOW, None).reason.unwrap()
}

#[test]
fn an_x5c_chain_must_be_signed_by_a_configured_root() {
    // the configured root is another certificate (the leaf): the chain top is not signed by its key
    assert_eq!(
        gcp_reason(LEAF_PEM),
        "Confidential Space signing key invalid: signing key not trusted: x5c chain does not anchor in a configured GCP trust root"
    );
    // its own root anchors it, so the verifier moves on to the signature (an ES256 token under a P-384 key)
    let r = gcp_reason(ROOT_PEM);
    assert!(r.starts_with("ES256 token but signing key is"), "{r}");
}

// ---- reservation receipts and sequencer key sets (direct: the pipeline shape-checks first) -----------------------------

const UNKNOWN: &str = "x-unknown-suite";

fn receipt(alg: Option<&str>) -> Value {
    let mut r = json!({
        "v": 1, "kind": "pca-acc-receipt", "session": b32(1), "acc": "trip_spend", "seq": 3, "pre": 10_000, "delta": 38_900, "post": 48_900,
        "pcactn_digest": b32(2), "aud": "skyair.example", "issued_at": NOW - 1_000, "expires_at": NOW + 60_000,
        "kid": "k1", "ledger": {"index": 7, "head": b32(3)}, "signer": b32(9), "sig": "AAAA"
    });
    if let Some(a) = alg {
        r["alg"] = json!(a);
    }
    r
}
fn key_set(alg: &str) -> Value {
    json!({
        "v": 1, "kind": "pca-sequencer-keys", "sequencer": b32(1), "version": 1, "issued_at": 5,
        "keys": [{"kid": "k1", "pk": b32(2), "not_before": 0}], "alg": alg, "sig": "AAAA"
    })
}

#[test]
fn a_receipt_signature_check_names_only_an_unsupported_suite() {
    let signer = b32(9);
    assert_eq!(seam::verify_acc_receipt_signature(&receipt(Some(UNKNOWN)), &signer), Err("receipt.alg: unsupported_suite: 'x-unknown-suite'".to_string()));
    // any other malformed receipt is simply not a valid signature
    assert_eq!(seam::verify_acc_receipt_signature(&json!({}), &signer), Ok(false));
    assert_eq!(seam::verify_acc_receipt_signature(&json!(5), &signer), Ok(false));
}

#[test]
fn a_key_set_check_names_only_an_unsupported_suite() {
    assert_eq!(seam::verify_sequencer_key_set(&key_set(UNKNOWN), &b32(1)), Err("alg: unsupported_suite: 'x-unknown-suite'".to_string()));
    assert_eq!(seam::verify_sequencer_key_set(&json!({}), &b32(1)), Ok(false));
}

#[test]
fn a_malformed_receipt_is_reported_as_such_unless_its_suite_is_unsupported() {
    let holder = Map::new();
    let run = |r: &Value| seam::verify_receipt_against_holder(r, &holder, None, NOW as f64, 60_000.0, 60_000.0);
    assert_eq!(run(&json!({})), Err("malformed receipt: not a pca-acc-receipt v1".to_string()));
    assert_eq!(run(&receipt(Some(UNKNOWN))), Err("receipt.alg: unsupported_suite: 'x-unknown-suite'".to_string()));
}

// ---- session root --------------------------------------------------------------------------------------------------

fn session_root() -> Value {
    json!({
        "v": 1, "kind": "pca-intent-session", "session": b32(1), "principals": [{"key": b32(2)}], "intent_ref": b32(3),
        "schema": {"aud": "a.example", "digest": b32(4)}, "layers": {"task": {"map_digest": b32(5)}},
        "accumulators": [], "monitors": [], "question_uri": "https://q.example/q", "expires_at": NOW, "signer": b32(2), "sig": "AAAA"
    })
}

#[test]
fn a_session_root_that_cannot_be_canonicalised_is_malformed() {
    assert_eq!(session_root_shape_error(&session_root()), None);
    let mut r = session_root();
    r["flows"] = json!({"x": 9_007_199_254_740_992u64});
    let e = session_root_shape_error(&r).expect("an integer outside the safe range cannot be signed");
    assert!(e.starts_with("malformed session root: "), "{e}");
}

// ---- mesh pin proofs -----------------------------------------------------------------------------------------------

fn mesh_reason(pin_proofs: Value) -> Option<String> {
    let trust = json!({"humanPrincipal": "h", "witnesses": ["w"], "threshold": 1, "now": 1000, "allowedDomains": ["d"], "rootDomain": "d"});
    let proof = json!({
        "chain": [], "hops": [], "heads": [], "rev_leaves": [], "action_sig": "x",
        "action": {"type": "t", "resource": "r", "service_domain": "d", "nonce": "n", "at": 1},
        "pin_proofs": pin_proofs
    });
    let v = verify_mesh_proof(&proof, &trust);
    assert!(!v.ok);
    v.reason
}

#[test]
fn a_pin_proof_needs_both_sizes() {
    assert_eq!(mesh_reason(json!([{"domain": "d", "proof": {"oldSize": 0, "newSize": 1, "path": []}}])).as_deref(), Some("chain length out of bounds"));
    assert_eq!(mesh_reason(json!([{"domain": "d", "proof": {"newSize": 1, "path": []}}])).as_deref(), Some("malformed pin proofs"));
    assert_eq!(mesh_reason(json!([{"domain": "d", "proof": {"oldSize": 0, "path": []}}])).as_deref(), Some("malformed pin proofs"));
}

// ---- middleware ----------------------------------------------------------------------------------------------------

#[cfg(feature = "axum")]
mod mw {
    use super::*;
    use atlas_pca::middleware::{GuardConfig, GuardResult, PcaLayer, PCA_ACTION_HEADER};
    use atlas_pca::{authorize, canonicalize_strict, AuthorizeInput, AuthorizeOptions, AuthorizeResult, MemoryStateStore, Operation};
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use std::convert::Infallible;
    use std::future::{ready, Future, Ready};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tower_layer::Layer;
    use tower_service::Service;

    #[test]
    fn the_json_body_carries_the_escalation_request() {
        let mut a = authorize(None, &AuthorizeInput::default());
        a.escalation = Some(json!({"request": {"id": "esc-1"}}));
        let g = GuardResult { allow: false, status: 403, error: Some("insufficient_authority"), description: "d".into(), pcactn: None, verdict: None, authorization: Some(a) };
        let b = g.json_body();
        assert_eq!(b["escalation"], json!({"request": {"id": "esc-1"}}));
        assert_eq!(b["decision"], json!("deny"));
    }

    fn block_on<F: Future>(mut fut: F) -> F::Output {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
        for _ in 0..1_000_000 {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            std::hint::spin_loop();
        }
        panic!("future did not resolve");
    }

    /// 418 when the guard handed the request on carrying its AuthorizeResult, 500 otherwise.
    #[derive(Clone)]
    struct Probe;
    impl Service<Request> for Probe {
        type Response = Response;
        type Error = Infallible;
        type Future = Ready<Result<Response, Infallible>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: Request) -> Self::Future {
            let ok = req.extensions().get::<AuthorizeResult>().is_some();
            ready(Ok((if ok { StatusCode::IM_A_TEAPOT } else { StatusCode::INTERNAL_SERVER_ERROR }).into_response()))
        }
    }

    #[test]
    fn an_allowed_request_carries_its_authorization_to_the_handler() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
        let d = atlas_pca::strict_parse(&text).unwrap();
        let c = d["cases"].as_array().unwrap().iter().find(|c| c["steps"][0]["expect"]["allow"] == Value::Bool(true)).unwrap();
        let s = &c["steps"][0];
        let op = Operation::from_json(&s["operation"]).unwrap();
        let grant = c["grant"].clone();
        let now = d["now"].as_i64().unwrap();
        let cfg = GuardConfig::new(d["audience"].as_str().unwrap().to_string(), move |_: &str| Some(grant.clone()))
            .with_clock(move || now)
            .with_authorize(
                AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false)).with_plan(Some(atlas_pca::SINGLE_STEP)).with_risk(atlas_pca::insecure_calm_risk)
                    .with_provenance_mediators(crate::common::harness_pins())
                    .with_provenance_bundle(crate::common::principal_direct),
            )
            .with_operation(move |_, _| Some(op.clone()));
        let header = URL_SAFE_NO_PAD.encode(canonicalize_strict(&s["pcactn"]).unwrap().as_bytes());
        let req = Request::builder().uri("/x").method("POST").header(PCA_ACTION_HEADER, header).body(Body::empty()).unwrap();
        let mut svc = PcaLayer::new(cfg).layer(Probe);
        let resp = block_on(svc.call(req)).unwrap();
        assert_eq!(resp.status(), StatusCode::IM_A_TEAPOT);
    }
}
