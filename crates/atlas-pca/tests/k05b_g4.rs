//! k05b g4: kill tests for the unledgered survivors of full run 42434682442 in sigstore.rs, attest/nvidia.rs, actions.rs,
//! workflow.rs, caveat_lang.rs, agent.rs and ledger.rs (survivor list rr1/surv-g4.txt). Every test drives the public API.
//! Fixtures that no shared vector holds are embedded at the end of this file; each was produced by the TypeScript reference
//! (test-support forgers / the k05 sigstore oracle PKI) and the reference's own verdict on it is quoted next to its test.
mod common;

use atlas_pca::actions::{closure, core_registry, schema_verb_floor_error, top_traits, Profile, Registry, TraitDef};
use atlas_pca::agent::{default_risk_policy, discharge_action_digest as producer_action_digest, mint_grant, mint_root, needs_discharge_caveat, sign_discharge, sign_narrow, KeyPair, PqKeyPair, Suite};
use atlas_pca::attest::nvidia::{parse_spdm, verify_device_chain};
use atlas_pca::attest::{run_attestation_vector, Binding};
use atlas_pca::sigstore::{parse_trusted_root, verify_sigstore_bundle_core};
use atlas_pca::workflow::{admit_step, AdmitInput};
use atlas_pca::{evaluate_k1, hash_canonical_strict, verify_narrow, DischargePin, K1Ctx, K1Input, NarrowBinding, NarrowVerdict};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Duration;

/// Run `f` on another thread: a loop that stops making progress fails the test instead of hanging it.
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("the call must terminate")
}

// =====================================================================================================================
// DER editing: rebuild a structure with one element replaced, every enclosing length recomputed
// =====================================================================================================================

/// (tag, body, total length) of the TLV at the start of `b`.
fn split(b: &[u8]) -> (u8, &[u8], usize) {
    let (n, hl) = if b[1] < 0x80 {
        (b[1] as usize, 2)
    } else {
        let k = (b[1] & 0x7f) as usize;
        (b[2..2 + k].iter().fold(0usize, |a, &c| a * 256 + c as usize), 2 + k)
    };
    (b[0], &b[hl..hl + n], hl + n)
}

fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut o = vec![tag];
    if n < 0x80 {
        o.push(n as u8);
    } else if n < 0x100 {
        o.extend([0x81, n as u8]);
    } else {
        o.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    o.extend_from_slice(body);
    o
}

/// The TLVs a body is made of.
fn kids(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut o = 0;
    while o < body.len() {
        let (_, _, total) = split(&body[o..]);
        out.push(&body[o..o + total]);
        o += total;
    }
    out
}

/// `der` with the element at child-index `path` replaced by `f(tag, body)` (the whole replacement TLV).
fn edit(der: &[u8], path: &[usize], f: &dyn Fn(u8, &[u8]) -> Vec<u8>) -> Vec<u8> {
    let (tag, body, _) = split(der);
    match path.split_first() {
        None => f(tag, body),
        Some((&i, rest)) => {
            let mut nb = Vec::new();
            for (j, k) in kids(body).into_iter().enumerate() {
                if j == i {
                    nb.extend(edit(k, rest, f));
                } else {
                    nb.extend_from_slice(k);
                }
            }
            wrap(tag, &nb)
        }
    }
}

fn same(t: u8, b: &[u8]) -> Vec<u8> {
    wrap(t, b)
}

/// Keep only the first `n` children.
fn keep(n: usize) -> impl Fn(u8, &[u8]) -> Vec<u8> {
    move |t, b| wrap(t, &kids(b).into_iter().take(n).flatten().copied().collect::<Vec<u8>>())
}

/// Same body, another tag.
fn retag(tag: u8) -> impl Fn(u8, &[u8]) -> Vec<u8> {
    move |_t, b| wrap(tag, b)
}

// =====================================================================================================================
// sigstore
// =====================================================================================================================

fn sigstore_doc() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/sigstore-vectors.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("read sigstore-vectors.json")).expect("parse")
    })
}

/// The verifying `synthetic/valid` bundle (a DSSE bundle with a certificate, one SET and one RFC 3161 timestamp) and its root.
fn synthetic() -> (Value, Value) {
    let d = sigstore_doc();
    let c = d["cases"].as_array().unwrap().iter().find(|c| c["name"] == "synthetic/valid").expect("synthetic/valid");
    (c["bundle"].clone(), d["roots"][c["roots"].as_str().unwrap()].clone())
}

/// (code, detail) of a refused bundle; an accepted one fails the test.
fn refusal(bundle: &Value, root: &Value) -> (String, String) {
    let roots = parse_trusted_root(root).unwrap_or_else(|e| panic!("root: {e}"));
    match verify_sigstore_bundle_core(bundle, &roots) {
        Err(e) => (e.code.to_string(), e.detail),
        Ok(c) => panic!("the bundle was accepted: {c:?}"),
    }
}

/// `new URL(baseUrl).hostname` names a Rekor v2 log in its signed notes; an IPv6 literal keeps its brackets and its colons.
/// The log id is sha256(name || "\n" || 0x01 || key), so a host cut at the first colon ("[2001") has no matching id.
#[test]
fn an_ipv6_literal_base_url_names_a_v2_log_by_its_bracketed_host() {
    let d = sigstore_doc();
    let root = d["roots"]["public-good-844a1c6d"].clone();
    parse_trusted_root(&root).expect("the unmodified root parses");
    let mut r = root;
    let tlog = r["tlogs"].as_array_mut().unwrap().iter_mut().find(|t| t["publicKey"]["keyDetails"] == "PKIX_ED25519").expect("an Ed25519 log");
    let spki = STANDARD.decode(tlog["publicKey"]["rawBytes"].as_str().unwrap()).unwrap();
    let raw = &spki[spki.len() - 32..];
    let name = "[2001:db8::1]";
    let mut m = format!("{name}\n").into_bytes();
    m.push(1);
    m.extend_from_slice(raw);
    tlog["baseUrl"] = json!("https://[2001:DB8::1]:8443/some/path");
    tlog["logId"]["keyId"] = json!(STANDARD.encode(Sha256::digest(&m)));
    if let Err(e) = parse_trusted_root(&r) {
        panic!("the bracketed, lower-cased host is the note name: {e}");
    }
}

/// A CT log keyed by RSA (PKCS#1) must have the SHA-256 of its SPKI as its id, like an ECDSA one.
#[test]
fn an_rsa_ct_log_id_must_hash_its_key() {
    let d = sigstore_doc();
    let root = d["roots"]["staging-e1d0c2ee"].clone();
    parse_trusted_root(&root).expect("the unmodified root parses");
    let mut r = root;
    let ct = r["ctlogs"].as_array_mut().unwrap().iter_mut().find(|t| t["publicKey"]["keyDetails"] == "PKCS1_RSA_PKCS1V5").expect("an RSA CT log");
    let mut id = STANDARD.decode(ct["logId"]["keyId"].as_str().unwrap()).unwrap();
    id[0] ^= 1;
    ct["logId"]["keyId"] = json!(STANDARD.encode(&id));
    assert_eq!(parse_trusted_root(&r).err().as_deref(), Some("log id is not the SHA-256 of its key"));
}

/// Bytes after a pinned certificate are refused (OpenSSL reads them as a second object; the root pins exactly one certificate).
#[test]
fn bytes_after_a_pinned_certificate_are_refused() {
    let d = sigstore_doc();
    let root = d["roots"]["synthetic-57b7cff6"].clone();
    parse_trusted_root(&root).expect("the unmodified root parses");
    let mut r = root;
    let cert = &mut r["certificateAuthorities"][0]["certChain"]["certificates"][0]["rawBytes"];
    let mut der = STANDARD.decode(cert.as_str().unwrap()).unwrap();
    der.push(0);
    *cert = json!(STANDARD.encode(&der));
    assert_eq!(parse_trusted_root(&r).err().as_deref(), Some("trailing bytes after the certificate"));
}

const TOKEN_TST_OCTET: [usize; 6] = [1, 1, 0, 2, 1, 0];

/// Edit inside the TSTInfo of a timestamp token (the content of the encapsulated OCTET STRING).
fn tst_edit(tok: &[u8], inner: &[usize], f: &dyn Fn(u8, &[u8]) -> Vec<u8>) -> Vec<u8> {
    edit(tok, &TOKEN_TST_OCTET, &|t, b| wrap(t, &edit(b, inner, f)))
}

fn set_token(bundle: &mut Value, tok: &[u8]) {
    bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"] = Value::String(STANDARD.encode(tok));
}

/// Each structural shortfall of an RFC 3161 token is refused with its own reason. A token that merely lacks the member is
/// otherwise indexed past its end (a panic caught and reported as "fail closed: panic"): the reason must be the named one.
#[test]
fn a_malformed_timestamp_token_is_refused_for_its_own_reason() {
    let (bundle, root) = synthetic();
    let tok = STANDARD.decode(bundle["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"][0]["signedTimestamp"].as_str().unwrap()).unwrap();
    // the editor rebuilds the token byte for byte, and the unmodified bundle verifies
    assert_eq!(edit(&tok, &[1, 1, 0, 3], &same), tok);
    assert_eq!(tst_edit(&tok, &[], &same), tok);
    assert!(verify_sigstore_bundle_core(&bundle, &parse_trusted_root(&root).unwrap()).is_ok());
    let cases: Vec<(Vec<u8>, &str)> = vec![
        // TSTInfo without its genTime (4 of the 5 members the reader needs)
        (tst_edit(&tok, &[], &keep(4)), "TSTInfo truncated"),
        // messageImprint without its digest
        (tst_edit(&tok, &[2], &keep(1)), "messageImprint malformed"),
        // genTime as a UTCTime (same digits): only a GeneralizedTime is a genTime
        (tst_edit(&tok, &[4], &retag(0x17)), "genTime is not a GeneralizedTime"),
        // SignerInfo without its signature
        (edit(&tok, &[1, 1, 0, 3, 0], &keep(5)), "SignerInfo truncated"),
        // the first signed attribute without its value set
        (edit(&tok, &[1, 1, 0, 3, 0, 3, 0], &keep(1)), "attribute malformed"),
    ];
    for (token, why) in cases {
        let mut b = bundle.clone();
        set_token(&mut b, &token);
        assert_eq!(refusal(&b, &root), ("tsa".to_string(), format!("fail closed: {why}")), "{why}");
    }
}

fn set_leaf(bundle: &mut Value, der: &[u8]) {
    bundle["verificationMaterial"]["certificate"]["rawBytes"] = Value::String(STANDARD.encode(der));
}

/// The leaf is read as OpenSSL's d2i_X509 reads it (`strict_x509`): each defect is refused with its named reason, not left to
/// surface later as a chain failure.
#[test]
fn the_leaf_certificate_is_read_strictly() {
    let (bundle, root) = synthetic();
    let leaf = STANDARD.decode(bundle["verificationMaterial"]["certificate"]["rawBytes"].as_str().unwrap()).unwrap();
    assert_eq!(edit(&leaf, &[0, 3], &same), leaf);
    assert!(verify_sigstore_bundle_core(&bundle, &parse_trusted_root(&root).unwrap()).is_ok());
    // TBSCertificate children: [0] version, serial, sigAlg, issuer, validity, subject, spki, [3] extensions
    let nested_junk = wrap(0x30, &wrap(0x30, &[0x04, 0x05]));
    let cases: Vec<(Vec<u8>, &str)> = vec![
        // bytes after the certificate
        ([leaf.clone(), vec![0]].concat(), "trailing bytes after the certificate"),
        // an issuer attribute value that is a SEQUENCE whose only member overruns it
        (edit(&leaf, &[0, 3, 0, 0, 1], &|_t, _b| wrap(0x30, &[0x04, 0x05])), "DER overrun"),
        // ... and one whose nested SEQUENCE is the malformed one
        (edit(&leaf, &[0, 3, 0, 0, 1], &|_t, _b| nested_junk.clone()), "DER overrun"),
        // a SubjectPublicKeyInfo BIT STRING claiming 8 unused bits
        (
            edit(&leaf, &[0, 6, 1], &|t, b| {
                let mut v = b.to_vec();
                v[0] = 8;
                wrap(t, &v)
            }),
            "certificate malformed (BIT STRING)",
        ),
        // an extension identifier that starts an arc with 0x80
        (edit(&leaf, &[0, 7, 0, 0, 0], &|t, _b| wrap(t, &[0x80, 0x55, 0x1d, 0x0f])), "certificate malformed (OID padding)"),
    ];
    for (i, (der, why)) in cases.into_iter().enumerate() {
        let mut b = bundle.clone();
        set_leaf(&mut b, &der);
        assert_eq!(refusal(&b, &root), ("cert_parse".to_string(), format!("fail closed: {why}")), "case {i}: {why}");
    }
}

/// A timestamp authority's certificate whose extension list cannot be read does not carry the timeStamping EKU. Reference
/// (the k05 oracle PKI, tsaOf with the same key and issuer): the unmodified chain verifies; the two certificates below are
/// the same certificate re-signed by the pinned root with (a) the EKU extension's value wrapped in a UTF8String instead of an
/// OCTET STRING, (b) the extension list wrapped in a SET instead of a SEQUENCE. OpenSSL refuses both certificates; here the
/// authority must at least never be used.
#[test]
fn a_timestamp_authority_certificate_with_unreadable_extensions_signs_nothing() {
    let root: Value = serde_json::from_str(TSA_ROOT_JSON).unwrap();
    let bundle: Value = serde_json::from_str(TSA_BUNDLE_JSON).unwrap();
    assert!(verify_sigstore_bundle_core(&bundle, &parse_trusted_root(&root).unwrap()).is_ok(), "the unmodified authority verifies");
    for (what, cert) in [("EKU value not an OCTET STRING", TSA_CERT_EKU_NOT_OCTET), ("extension list not a SEQUENCE", TSA_CERT_EXTS_NOT_SEQUENCE)] {
        let mut r = root.clone();
        r["timestampAuthorities"][0]["certChain"]["certificates"][0]["rawBytes"] = json!(cert);
        assert_eq!(refusal(&bundle, &r), ("tsa".to_string(), "fail closed: no pinned timestamp authority signed it (valid at its time)".to_string()), "{what}");
    }
}

// =====================================================================================================================
// NVIDIA
// =====================================================================================================================

/// request || response with no measurement blocks and the given opaque data (the layout of the SPDM tests of the crate).
fn transcript(opaque: &[u8]) -> Vec<u8> {
    let mut b = vec![0x11, 0xe0, 0, 0];
    b.extend_from_slice(&[7; 32]);
    b.push(0);
    b.extend_from_slice(&[0x11, 0x60, 0, 0, 0]);
    b.extend_from_slice(&0u32.to_le_bytes()[..3]);
    b.extend_from_slice(&[8; 32]);
    b.extend_from_slice(&(opaque.len() as u16).to_le_bytes());
    b.extend_from_slice(opaque);
    b.extend_from_slice(&[9; 96]);
    b
}

#[test]
fn an_opaque_tlv_longer_than_the_opaque_data_is_refused() {
    // type 3, length 5, one value byte: the value runs past the opaque data
    assert_eq!(parse_spdm(&transcript(&[3, 0, 5, 0, 0xaa])).err().as_deref(), Some("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data"));
    // a value that ends exactly at the end of the opaque data is fine
    let s = parse_spdm(&transcript(&[3, 0, 1, 0, 0xaa])).ok().expect("a TLV may end the opaque data exactly");
    assert_eq!(s.opaque.get(&3), Some(&vec![0xaa]));
}

#[test]
fn a_device_chain_of_more_than_five_certificates_is_refused_before_it_is_read() {
    let block = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    assert_eq!(verify_device_chain(&block.repeat(6), &[], 0.0).err().as_deref(), Some("device chain unparseable: parsePemChain: chain longer than 5"));
    // five are read (and fail on their content, not on their number)
    let e = verify_device_chain(&block.repeat(5), &[], 0.0).err().expect("garbage certificates are refused");
    assert!(e.starts_with("device chain unparseable: ") && !e.contains("chain longer"), "{e}");
}

fn att_doc() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| common::load("attestation-evidence-vectors.json"))
}

fn hydrate(x: &Value, blobs: &Map<String, Value>) -> Value {
    match x {
        Value::Array(a) => Value::Array(a.iter().map(|e| hydrate(e, blobs)).collect()),
        Value::Object(o) => {
            if o.len() == 1 {
                if let Some(id) = o.get("$blob").and_then(Value::as_str) {
                    return blobs.get(id).cloned().unwrap_or_else(|| panic!("unknown blob {id}"));
                }
            }
            Value::Object(o.iter().map(|(k, v)| (k.clone(), hydrate(v, blobs))).collect())
        }
        other => other.clone(),
    }
}

/// The synthetic NVIDIA scenario with the collateral hook that passes (`nv-syn-col-positive-crl`), hydrated.
struct NvRow {
    cfg: Value,
    ev: Value,
    now: i64,
    binding: Binding,
    expect: Value,
}

fn nv_row() -> NvRow {
    let d = att_doc();
    let blobs = d["blobs"].as_object().unwrap();
    let r = d["attestation_vectors"].as_array().unwrap().iter().find(|r| r["id"] == "nv-syn-col-positive-crl").expect("nv-syn-col-positive-crl");
    let b = &r["expected_binding"];
    NvRow {
        cfg: hydrate(&r["config"], blobs),
        ev: hydrate(&r["evidence"], blobs),
        now: r["now"].as_f64().unwrap() as i64,
        binding: Binding { holder_pub: b["holderPub"].as_str().unwrap().to_string(), grant_ref: b["grantRef"].as_str().unwrap().to_string(), epoch: b["epoch"].as_f64().unwrap(), nonce: b["nonce"].as_str().unwrap().to_string() },
        expect: r["expect"].clone(),
    }
}

impl NvRow {
    fn run(&self, cfg: &Value, ev: &Value) -> Value {
        run_attestation_vector("nvidia-gpu-spdm", cfg, Some(ev), self.now, Some(&self.binding))
    }
    fn denial(reason: &str) -> Value {
        json!({ "ok": false, "reason": reason })
    }
}

/// A VBIOS floor at or below the reported VBIOS passes; one above it is refused (reference: firmware floors compare as
/// dotted hex, attest-nvidia-spdm.ts).
#[test]
fn a_vbios_floor_refuses_only_a_lower_vbios() {
    let row = nv_row();
    assert_eq!(row.run(&row.cfg, &row.ev), row.expect, "the scenario passes unmodified");
    for min in ["96.00.9f.00.04", "01.00.00.00.00"] {
        let mut cfg = row.cfg.clone();
        cfg["collateral"]["firmware"] = json!({ "minVbiosVersion": min });
        assert_eq!(row.run(&cfg, &row.ev), row.expect, "floor {min}");
    }
    let mut cfg = row.cfg.clone();
    cfg["collateral"]["firmware"] = json!({ "minVbiosVersion": "96.00.a0.00.04" });
    assert_eq!(row.run(&cfg, &row.ev), NvRow::denial("firmware policy: VBIOS 96.00.9f.00.04 is below the minimum 96.00.a0.00.04"));
}

fn with_rims(row: &NvRow, driver: &str, vbios: &str) -> Value {
    let mut ev = row.ev.clone();
    ev["collateral"]["driverRimXml"] = json!(driver);
    ev["collateral"]["vbiosRimXml"] = json!(vbios);
    ev["collateral"]["ocsp"] = json!([]);
    ev
}

/// Reference verdicts (the TypeScript verifier over the same configuration and evidence, RIMs signed by the scenario's CoRIM
/// chain with one measurement each): both RIMs active at index 0 -> "driver and VBIOS RIMs both have an active measurement at
/// index 0"; both RIMs with only inactive entries -> "RIMs carry no active golden measurements".
#[test]
fn reference_manifests_must_partition_the_active_measurements_and_carry_some() {
    let row = nv_row();
    assert_eq!(row.run(&row.cfg, &with_rims(&row, NV_OVERLAP_DRIVER_RIM, NV_OVERLAP_VBIOS_RIM)), NvRow::denial("driver and VBIOS RIMs both have an active measurement at index 0"));
    assert_eq!(row.run(&row.cfg, &with_rims(&row, NV_EMPTY_DRIVER_RIM, NV_EMPTY_VBIOS_RIM)), NvRow::denial("RIMs carry no active golden measurements"));
}

/// A CRL is checked against the FIRST chain certificate whose key verifies it (the reference's `find`), and the certificate it
/// can revoke is the one just below that issuer. The Identity certificate here carries the root's key, so the same CRL
/// verifies under two chain certificates: the revoked Provisioner ICA is only caught when the lower of the two is the issuer.
/// Reference: "revocation: chain certificate 'CN=NVIDIA GH100 Provisioner ICA 1, O=NVIDIA Corporation, C=US' is revoked".
#[test]
fn a_crl_is_attributed_to_the_first_chain_certificate_that_verifies_it() {
    let row = nv_row();
    let mut ev = row.ev.clone();
    ev["certChainPem"] = json!(NV_SHARED_KEY_CHAIN_PEM);
    ev["collateral"]["crls"] = json!(NV_SHARED_KEY_CRLS);
    ev["collateral"]["ocsp"] = json!([]);
    assert_eq!(row.run(&row.cfg, &ev), NvRow::denial("revocation: chain certificate 'CN=NVIDIA GH100 Provisioner ICA 1, O=NVIDIA Corporation, C=US' is revoked"));
}

// =====================================================================================================================
// actions
// =====================================================================================================================

/// `closure` visits each trait once: a registry whose traits imply each other (build_registry refuses one, closure is public)
/// still terminates.
#[test]
fn the_trait_closure_visits_each_trait_once() {
    let got = within(|| {
        let t = |id: &str, implies: &str| TraitDef { id: id.into(), implies: vec![implies.into()], floor: Profile::bottom(), card_phrase: String::new() };
        let reg = Registry { traits: [("a", t("a", "b")), ("b", t("b", "a"))].into_iter().map(|(k, v)| (k.to_string(), v)).collect() };
        closure(&reg, &["a".to_string(), "a".to_string()]).map_err(|e| e.to_string())
    });
    assert_eq!(got, Ok(vec!["a".to_string(), "b".to_string()]));
}

/// A v2 verb whose `floors` is null (present but null) is a malformed verb, not a verb whose floors are merely too low.
#[test]
fn a_null_floors_member_is_malformed() {
    let reg = core_registry();
    let verb = |floors: Value| json!({ "effects": [], "traits": top_traits(&reg), "floors": floors, "params": {} });
    assert_eq!(schema_verb_floor_error(&verb(Value::Null), &reg, None).as_deref(), Some("schema_floor_forged: malformed verb: floors"));
    assert_eq!(schema_verb_floor_error(&verb(json!({})), &reg, None).as_deref(), Some("schema_floor_forged: floors are below the floor of the carried traits"));
}

// =====================================================================================================================
// workflow
// =====================================================================================================================

fn workflow_doc() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/workflow-vectors.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("read workflow-vectors.json")).expect("parse")
    })
}

/// admit_step over the `main` workflow of the shared vectors at their clock, with receipts signed by the vectors' receipt
/// signer (the same Ed25519 seed the TypeScript generator uses; the receipts below were produced by its signStepReceipt).
fn admit(receipts: &[&str], request: &str) -> Value {
    let w = workflow_doc();
    let receipts = Value::Array(receipts.iter().map(|r| serde_json::from_str(r).unwrap()).collect());
    let request: Value = serde_json::from_str(request).unwrap();
    let now = json!(1_800_000_000_000i64);
    let inp = AdmitInput { workflow: &w["workflows"]["main"], principal: &w["keys"]["principal"], rs_signer: &w["keys"]["rs"], receipts: &receipts, now: &now, request: &request };
    admit_step(&inp).to_json()
}

fn decided(decision: &str, code: Option<&str>, step: &str, at: Option<usize>) -> Value {
    json!({ "decision": decision, "code": code, "step": step, "at": at, "pending": [] })
}

/// Two receipts for one step are refused even when each is signed, in sequence and chained to the one before (reference
/// admitStep: deny bad_receipt at 1).
#[test]
fn a_second_receipt_for_the_same_step_is_refused() {
    assert_eq!(admit(&[WF_LOOKUP], WF_REQ_REFUND), decided("allow", None, "refund", None), "one lookup receipt admits the refund");
    assert_eq!(admit(&[WF_LOOKUP, WF_LOOKUP_AGAIN], WF_REQ_REFUND), decided("deny", Some("bad_receipt"), "refund", Some(1)));
}

/// An edge's deny_labels apply to the very output flowing along it, and the denial names that edge (index 2: refund.confirmation
/// -> notify.ref). The step-level taint check would also refuse, without an edge index. Reference: deny taint_flow at 2.
#[test]
fn a_label_on_the_value_an_edge_carries_denies_at_that_edge() {
    assert_eq!(admit(&[WF_LOOKUP, WF_REFUND_CLEAN], WF_REQ_NOTIFY), decided("allow", None, "notify", None), "without the label the notify is admitted");
    assert_eq!(admit(&[WF_LOOKUP, WF_REFUND_SECRET_CONFIRMATION], WF_REQ_NOTIFY), decided("deny", Some("taint_flow"), "notify", Some(2)));
}

// =====================================================================================================================
// caveat language
// =====================================================================================================================

/// When several discharges for one caveat verify, the FIRST supplies the claims (reference evaluateK1 breaks at the first ok).
#[test]
fn the_first_verifying_discharge_supplies_the_claims() {
    let issuer = KeyPair::from_seed(&[11u8; 32]);
    let nd = needs_discharge_caveat("d1", "idp", "human", "chain_hop", 60_000, json!([]));
    let dv = json!({ "type": "derive", "id": "dv", "defs": [{ "name": "tier", "kind": "claim", "caveat_id": "d1", "claim": "tier" }], "check": { "op": "eq", "a": { "ref": "tier" }, "b": { "const": "gold" } } });
    let grant = json!({ "caveats": [nd, dv] });
    let cap_hash = hash_canonical_strict(&grant).unwrap();
    let mk = |tier: &str| sign_discharge(&issuer, "d1", "idp", &cap_hash, "chain_hop", None, &json!({ "tier": tier }), 1_000, 2_000, None, &Suite::default()).unwrap();
    let pin = DischargePin { label: "idp".into(), class: "human".into(), pk: issuer.public.clone(), pq_pk: None, spiffe_id: None };
    let run = |ds: Vec<Value>| evaluate_k1(&grant, &Value::Null, Some(&K1Input { pins: vec![pin.clone()], discharges: ds, ..Default::default() }), &K1Ctx { now: 1_500, action: None });
    let lone = run(vec![mk("gold")]);
    assert!(lone.ok, "{:?}", lone.reasons);
    let gold_first = run(vec![mk("gold"), mk("basic")]);
    assert!(gold_first.ok, "{:?}", gold_first.reasons);
    let basic_first = run(vec![mk("basic"), mk("gold")]);
    assert!(!basic_first.ok);
    assert_eq!((basic_first.failed, basic_first.reasons), (vec!["derive".to_string()], vec!["derive check is false".to_string()]));
}

// =====================================================================================================================
// agent
// =====================================================================================================================

/// A narrow block signed for one action carries that action's digest (signed with the block), so it cannot be replayed on another.
#[test]
fn a_narrow_block_carries_the_action_digest_it_was_signed_for() {
    let (principal, key) = (KeyPair::from_seed(&[3u8; 32]), KeyPair::from_seed(&[4u8; 32]));
    let env = json!({ "predicates": [{ "verb": "refund", "resource": "orders/*" }], "caveats": [], "risk_policy": default_risk_policy() });
    let grant = mint_grant(&principal, &key.public, &env, "refund an order", None, None, &Suite::default()).unwrap().grant;
    let leaf = hash_canonical_strict(&grant).unwrap();
    let ad = producer_action_digest(&json!({ "a": 1 })).unwrap();
    let other = producer_action_digest(&json!({ "a": 2 })).unwrap();
    let (iat, na) = (1_800_000_000_000i64, 1_800_000_060_000i64);
    let caveats = json!([{ "type": "expires", "at": na }]);
    let n = sign_narrow(&key, &leaf, &caveats, iat, na, Some(&ad), None, &Suite::default()).unwrap();
    assert_eq!(n["action_digest"], json!(ad));
    match verify_narrow(&n, &grant, &Value::Null, &NarrowBinding { now: iat + 1, action_digest: Some(&ad) }) {
        NarrowVerdict::Ok { .. } => {}
        v => panic!("the action it was signed for was refused: {v:?}"),
    }
    match verify_narrow(&n, &grant, &Value::Null, &NarrowBinding { now: iat + 1, action_digest: Some(&other) }) {
        NarrowVerdict::Fail { reason } => assert_eq!(reason, "the narrow block is bound to another action"),
        v => panic!("another action verified: {v:?}"),
    }
}

/// A capability sealed under a hybrid suite carries its post-quantum signature next to the Ed25519 one.
#[test]
fn a_capability_under_a_hybrid_suite_carries_its_pq_signature() {
    let pq = PqKeyPair::generate("ML-DSA-65").unwrap();
    let suite = Suite { alg: Some("hybrid-ed25519-ml-dsa-65"), pq: Some(&pq) };
    let (principal, holder) = (KeyPair::from_seed(&[3u8; 32]), KeyPair::from_seed(&[4u8; 32]));
    let cap = mint_root(&principal, &holder.public, &json!([]), None, &suite).unwrap();
    assert_eq!(cap["alg"], json!("hybrid-ed25519-ml-dsa-65"));
    assert_eq!(cap["pq_pk"], json!(pq.public));
    assert!(cap["pq_sig"].as_str().is_some_and(|s| !s.is_empty()), "no pq_sig on {cap}");
    assert!(cap["sig"].as_str().is_some_and(|s| !s.is_empty()));
}

// =====================================================================================================================
// embedded fixtures (see the notes at the top of the file)
// =====================================================================================================================

const NV_OVERLAP_DRIVER_RIM: &str = r####"<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns0="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns2="http://www.w3.org/2001/04/xmlenc#sha384" corpus="false" name="GH100" patch="false" supplemental="false" tagId="89f1cc4e67917fe001fc246a0f5eed8832754500360c1e1a2ad67c4be82a1ee52deeb12e84021f849faffc048abe4d1e" version="1.0" tagVersion="0">
    <ns0:Entity name="NVIDIA Corporation" role="softwareCreator tagCreator"/>
    <ns0:Meta xmlns:ns1="https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/" colloquialVersion="595.71.05" edition="GPU" product="GH100" revision="r1" PayloadType="direct" ns1:BindingSpec="RIMIM" ns1:BindingSpecVersion="1.01" ns1:PlatformManufacturerId="5703" ns1:PlatformManufacturerStr="NVIDIA Corporation" ns1:PlatformModel="GH100" ns1:FirmwareManufacturer="NVIDIA Corporation" ns1:FirmwareManufacturerId="5703"/>
    <ns0:Payload xmlns:SHA384="http://www.w3.org/2001/04/xmlenc#sha384">
        <ns0:Resource type="Measurement" index="0" active="True" alternatives="1" ns2:Hash0="c863d8fe52e8af320f58fcfe4043be13dab4d58db9959d9da5a9d665fe8f0697247c11db0bf608c5e4b8e371a8858a06" name="Measurement_0" size="48"/>
    </ns0:Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/><ds:DigestValue>DnyAIxf1z1pYsRZ+x9be4krdj54h6nEBiVAhvQRZZ/v2MaJ8dcUi2fl0WpsjF2pr</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>j46+Z3VB7iHyQPimPG1EsUfgd4u60ahaTReODoVjTBqqqCmsyFgWwXWloFRbiDak9P5OuplGSaOaYzfgwmUlZ3emxclzM6fsrKPPvzDshEeTvTuz0EiGlgD4Jlceqexh</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICUzCCAdqgAwIBAgIUcdbjrGZa0/vHc5UkqiWsijIrzBswCgYIKoZIzj0EAwMwTDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTEsMCoGA1UEAwwjTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBMMyBHSDEwMCAwMDMwHhcNMjYwMzEyMjMzODEzWhcNMjgwMzExMjMzODEzWjBpMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRswGQYDVQQKDBJOVklESUEgQ29ycG9yYXRpb24xGjAYBgNVBAMMEUhDQyBSSU0gTDQgU2lnbmVyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE97yTAJrx9j/Ree0NffyNEqp9HjxYaTXe/I1zt4xcYDsBkW59Jg2RbmQDlZRLjIsUj1KnmzdaKHwV8XK52LFT8TezKLVruFHt+/qSXNSaWJiMUqkfwRvkxFnaunnZ2J3vo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUUxewc+HYekLZRTVOtuB88qHZ8F4wHwYDVR0jBBgwFoAUCN6b39JES4tqzYcfk+/rlnmmJp0wCgYIKoZIzj0EAwMDZwAwZAIwGu4dcIcsvQHjB6vr2ET3WwAS6iULSNpkVVlAdrLysLLv/NhZerNs4X8+uyBm7TjEAjBnqNvNV/uimZ3TIrEYHdjlWuuesFW4VkCnSjgu+qIlM7fv9RWmpIzicbdPwj3WkHs=</ds:X509Certificate><ds:X509Certificate>MIICRTCCAcugAwIBAgIUWYZtwAiXMdj7MqzcsLOLUlixxRkwCgYIKoZIzj0EAwMwVDEoMCYGA1UEAwwfTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBHSDEwMCBDQTEbMBkGA1UECgwSTlZJRElBIENvcnBvcmF0aW9uMQswCQYDVQQGEwJVUzAeFw0yNTExMDcwMDAwMDBaFw0zNTExMDcyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZOVklESUExLDAqBgNVBAMMI05WSURJQSBSZWZlcmVuY2UgVmFsdWUgTDMgR0gxMDAgMDAzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEpD72UkkBlkN+ge6DITAvfncLg05JGClkKte0fhwXX2HUHeA8MreZa1SMiABv3bw+xZLPf3ZUAr6Rbrai/H9sSoRs+RZzQzAGN8dnoRbqzvmaBMNpLIFdE2HnGHPqqh5Qo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUCN6b39JES4tqzYcfk+/rlnmmJp0wHwYDVR0jBBgwFoAUb8VzvJ66ROWxzPC8KsU3unR8AdQwCgYIKoZIzj0EAwMDaAAwZQIwRwHU/rGpyktNgROIFP2/uuM9xsIWP6EO8EvBOkc0/U95AduXMwl6kHHxX8qPGYWNAjEAxaps4b0ovexhFbUpSUe/eLvxoP1S8adH9lkdJLSjJMDp+B/YfTQew60DJzMxYZZI</ds:X509Certificate><ds:X509Certificate>MIICOjCCAcGgAwIBAgIUQBY9MlCkUevj+yYa6C0Lzmc4YpgwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAeFw0yMzA1MTEwMDAwMDBaFw0zMzA1MTEyMzU5NTlaMFQxKDAmBgNVBAMMH05WSURJQSBSZWZlcmVuY2UgVmFsdWUgR0gxMDAgQ0ExGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATbokXf+6PBMDB8cYUztr9ZbuzFnKiMaVzB7BSVVPCGxi4TR60o3jigeLgxsTua5dA3tKvyt6nuWrZtiI+ibNFsIx5sUtuWHN9T6qACPp63+Wc08qnpmGUTkOrqnuFUkIGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRvxXO8nrpE5bHM8LwqxTe6dHwB1DAfBgNVHSMEGDAWgBQf5L2bUUtkgFR84VAklxpTMwKKJzAKBggqhkjOPQQDAwNnADBkAjBPVKiwgeVonJ3JDJd3re+cgDiloqiNuuTRYLwaMRubU25ZoFwO3EP0yOhf8+9Szg8CMDqgbk5+sJ5IGzpVS1qQqTnWHir8xvx0OKHmg8CLgbpBUIdD759OUcvVnliE7ihsnQ==</ds:X509Certificate><ds:X509Certificate>MIICLjCCAbSgAwIBAgIUc+13azQDRQFlzeZ6FNFuDmHxp0gwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAgFw0yMzAzMTYxNTM3MzRaGA8yMDUzMDMwODE1MzczNFowRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCVxTuS9lz2zaDBXySJTQvitTQ18Ev7/qbuV9pE3vaIBShXBvZPi15zK+uUbL7UX1U8dFxs/W9448Qz01J/BK6+/0tBBqENPFUUMLeLjimizRJxzzzeErJPT5AziesRDvaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFB/kvZtRS2SAVHzhUCSXGlMzAoonMB8GA1UdIwQYMBaAFB/kvZtRS2SAVHzhUCSXGlMzAoonMAoGCCqGSM49BAMDA2gAMGUCMQDwq2lsRdvK5JUNnYZinwYG2ENgxsJkWdHB+RXqmZC3HrjinNZtNz0/8UUdUGWFD3MCMAHOL+pJyRxG2rS40IjLQK/M+phPoXL01lh2aFhy/+iZCmR+bpquQVTcMTHlqeZ7dA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
"####;
const NV_OVERLAP_VBIOS_RIM: &str = r####"<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns0="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns2="http://www.w3.org/2001/04/xmlenc#sha384" corpus="false" name="GH100" patch="false" supplemental="false" tagId="7b76d44342795077b92b7ef5f1e8a97c0e56804312af879959d7fabac6bdb91eb82e43cdf42e5bf4fbd20c0b340657a4" version="1.0" tagVersion="0">
    <ns0:Entity name="NVIDIA Corporation" role="softwareCreator tagCreator"/>
    <ns0:Meta xmlns:ns1="https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/" colloquialVersion="96.00.9F.00.04" edition="GPU" product="GH100" revision="r1" PayloadType="direct" ns1:BindingSpec="RIMIM" ns1:BindingSpecVersion="1.01" ns1:PlatformManufacturerId="5703" ns1:PlatformManufacturerStr="NVIDIA Corporation" ns1:PlatformModel="GH100" ns1:FirmwareManufacturer="NVIDIA Corporation" ns1:FirmwareManufacturerId="5703"/>
    <ns0:Payload xmlns:SHA384="http://www.w3.org/2001/04/xmlenc#sha384">
        <ns0:Resource type="Measurement" index="0" active="True" alternatives="1" ns2:Hash0="c863d8fe52e8af320f58fcfe4043be13dab4d58db9959d9da5a9d665fe8f0697247c11db0bf608c5e4b8e371a8858a06" name="Measurement_0" size="48"/>
    </ns0:Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/><ds:DigestValue>AUMUTtCXN0uuJJXLnf4qaZB4blTUPpi8gBlwwb2URSs9Zl8fg2WHNxzqV4MoY8+d</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>RkqqtPTYo1kfG0LnEyIPBkzLU30gOGFvTvwv/YTEHXOpmHfnxwiUX3UG1Q9bnW6rnMRhq6vH5/l34p1fGMZHAZev4xlUnfIGe/UfvBNZrk1aOdG1PRS7WF/uS24doNf4</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICUzCCAdqgAwIBAgIUcdbjrGZa0/vHc5UkqiWsijIrzBswCgYIKoZIzj0EAwMwTDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTEsMCoGA1UEAwwjTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBMMyBHSDEwMCAwMDMwHhcNMjYwMzEyMjMzODEzWhcNMjgwMzExMjMzODEzWjBpMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRswGQYDVQQKDBJOVklESUEgQ29ycG9yYXRpb24xGjAYBgNVBAMMEUhDQyBSSU0gTDQgU2lnbmVyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE97yTAJrx9j/Ree0NffyNEqp9HjxYaTXe/I1zt4xcYDsBkW59Jg2RbmQDlZRLjIsUj1KnmzdaKHwV8XK52LFT8TezKLVruFHt+/qSXNSaWJiMUqkfwRvkxFnaunnZ2J3vo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUUxewc+HYekLZRTVOtuB88qHZ8F4wHwYDVR0jBBgwFoAUCN6b39JES4tqzYcfk+/rlnmmJp0wCgYIKoZIzj0EAwMDZwAwZAIwGu4dcIcsvQHjB6vr2ET3WwAS6iULSNpkVVlAdrLysLLv/NhZerNs4X8+uyBm7TjEAjBnqNvNV/uimZ3TIrEYHdjlWuuesFW4VkCnSjgu+qIlM7fv9RWmpIzicbdPwj3WkHs=</ds:X509Certificate><ds:X509Certificate>MIICRTCCAcugAwIBAgIUWYZtwAiXMdj7MqzcsLOLUlixxRkwCgYIKoZIzj0EAwMwVDEoMCYGA1UEAwwfTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBHSDEwMCBDQTEbMBkGA1UECgwSTlZJRElBIENvcnBvcmF0aW9uMQswCQYDVQQGEwJVUzAeFw0yNTExMDcwMDAwMDBaFw0zNTExMDcyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZOVklESUExLDAqBgNVBAMMI05WSURJQSBSZWZlcmVuY2UgVmFsdWUgTDMgR0gxMDAgMDAzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEpD72UkkBlkN+ge6DITAvfncLg05JGClkKte0fhwXX2HUHeA8MreZa1SMiABv3bw+xZLPf3ZUAr6Rbrai/H9sSoRs+RZzQzAGN8dnoRbqzvmaBMNpLIFdE2HnGHPqqh5Qo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUCN6b39JES4tqzYcfk+/rlnmmJp0wHwYDVR0jBBgwFoAUb8VzvJ66ROWxzPC8KsU3unR8AdQwCgYIKoZIzj0EAwMDaAAwZQIwRwHU/rGpyktNgROIFP2/uuM9xsIWP6EO8EvBOkc0/U95AduXMwl6kHHxX8qPGYWNAjEAxaps4b0ovexhFbUpSUe/eLvxoP1S8adH9lkdJLSjJMDp+B/YfTQew60DJzMxYZZI</ds:X509Certificate><ds:X509Certificate>MIICOjCCAcGgAwIBAgIUQBY9MlCkUevj+yYa6C0Lzmc4YpgwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAeFw0yMzA1MTEwMDAwMDBaFw0zMzA1MTEyMzU5NTlaMFQxKDAmBgNVBAMMH05WSURJQSBSZWZlcmVuY2UgVmFsdWUgR0gxMDAgQ0ExGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATbokXf+6PBMDB8cYUztr9ZbuzFnKiMaVzB7BSVVPCGxi4TR60o3jigeLgxsTua5dA3tKvyt6nuWrZtiI+ibNFsIx5sUtuWHN9T6qACPp63+Wc08qnpmGUTkOrqnuFUkIGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRvxXO8nrpE5bHM8LwqxTe6dHwB1DAfBgNVHSMEGDAWgBQf5L2bUUtkgFR84VAklxpTMwKKJzAKBggqhkjOPQQDAwNnADBkAjBPVKiwgeVonJ3JDJd3re+cgDiloqiNuuTRYLwaMRubU25ZoFwO3EP0yOhf8+9Szg8CMDqgbk5+sJ5IGzpVS1qQqTnWHir8xvx0OKHmg8CLgbpBUIdD759OUcvVnliE7ihsnQ==</ds:X509Certificate><ds:X509Certificate>MIICLjCCAbSgAwIBAgIUc+13azQDRQFlzeZ6FNFuDmHxp0gwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAgFw0yMzAzMTYxNTM3MzRaGA8yMDUzMDMwODE1MzczNFowRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCVxTuS9lz2zaDBXySJTQvitTQ18Ev7/qbuV9pE3vaIBShXBvZPi15zK+uUbL7UX1U8dFxs/W9448Qz01J/BK6+/0tBBqENPFUUMLeLjimizRJxzzzeErJPT5AziesRDvaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFB/kvZtRS2SAVHzhUCSXGlMzAoonMB8GA1UdIwQYMBaAFB/kvZtRS2SAVHzhUCSXGlMzAoonMAoGCCqGSM49BAMDA2gAMGUCMQDwq2lsRdvK5JUNnYZinwYG2ENgxsJkWdHB+RXqmZC3HrjinNZtNz0/8UUdUGWFD3MCMAHOL+pJyRxG2rS40IjLQK/M+phPoXL01lh2aFhy/+iZCmR+bpquQVTcMTHlqeZ7dA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
"####;
const NV_EMPTY_DRIVER_RIM: &str = r####"<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns0="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns2="http://www.w3.org/2001/04/xmlenc#sha384" corpus="false" name="GH100" patch="false" supplemental="false" tagId="89f1cc4e67917fe001fc246a0f5eed8832754500360c1e1a2ad67c4be82a1ee52deeb12e84021f849faffc048abe4d1e" version="1.0" tagVersion="0">
    <ns0:Entity name="NVIDIA Corporation" role="softwareCreator tagCreator"/>
    <ns0:Meta xmlns:ns1="https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/" colloquialVersion="595.71.05" edition="GPU" product="GH100" revision="r1" PayloadType="direct" ns1:BindingSpec="RIMIM" ns1:BindingSpecVersion="1.01" ns1:PlatformManufacturerId="5703" ns1:PlatformManufacturerStr="NVIDIA Corporation" ns1:PlatformModel="GH100" ns1:FirmwareManufacturer="NVIDIA Corporation" ns1:FirmwareManufacturerId="5703"/>
    <ns0:Payload xmlns:SHA384="http://www.w3.org/2001/04/xmlenc#sha384">
        <ns0:Resource type="Measurement" index="0" active="False" alternatives="1" ns2:Hash0="c863d8fe52e8af320f58fcfe4043be13dab4d58db9959d9da5a9d665fe8f0697247c11db0bf608c5e4b8e371a8858a06" name="Measurement_0" size="48"/>
    </ns0:Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/><ds:DigestValue>rLaJ+Cvvt4V+/FAhOtXyvbAcSyXUzmOkPw5tiw4S+MMSkK1yxKQzWjt25bX+yRSQ</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>xwNANzbVG5OG6hloadO2GGXR0PxiADPRq6xoet07olUKItbwjSI9XwHzAqoylEloJIjraku/lYqIm2udJeTzxLWBTgLVhKtS8uOb4jhS47Tz0uoVhOkQgD1sSCOrgkbA</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICUzCCAdqgAwIBAgIUcdbjrGZa0/vHc5UkqiWsijIrzBswCgYIKoZIzj0EAwMwTDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTEsMCoGA1UEAwwjTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBMMyBHSDEwMCAwMDMwHhcNMjYwMzEyMjMzODEzWhcNMjgwMzExMjMzODEzWjBpMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRswGQYDVQQKDBJOVklESUEgQ29ycG9yYXRpb24xGjAYBgNVBAMMEUhDQyBSSU0gTDQgU2lnbmVyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE97yTAJrx9j/Ree0NffyNEqp9HjxYaTXe/I1zt4xcYDsBkW59Jg2RbmQDlZRLjIsUj1KnmzdaKHwV8XK52LFT8TezKLVruFHt+/qSXNSaWJiMUqkfwRvkxFnaunnZ2J3vo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUUxewc+HYekLZRTVOtuB88qHZ8F4wHwYDVR0jBBgwFoAUCN6b39JES4tqzYcfk+/rlnmmJp0wCgYIKoZIzj0EAwMDZwAwZAIwGu4dcIcsvQHjB6vr2ET3WwAS6iULSNpkVVlAdrLysLLv/NhZerNs4X8+uyBm7TjEAjBnqNvNV/uimZ3TIrEYHdjlWuuesFW4VkCnSjgu+qIlM7fv9RWmpIzicbdPwj3WkHs=</ds:X509Certificate><ds:X509Certificate>MIICRTCCAcugAwIBAgIUWYZtwAiXMdj7MqzcsLOLUlixxRkwCgYIKoZIzj0EAwMwVDEoMCYGA1UEAwwfTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBHSDEwMCBDQTEbMBkGA1UECgwSTlZJRElBIENvcnBvcmF0aW9uMQswCQYDVQQGEwJVUzAeFw0yNTExMDcwMDAwMDBaFw0zNTExMDcyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZOVklESUExLDAqBgNVBAMMI05WSURJQSBSZWZlcmVuY2UgVmFsdWUgTDMgR0gxMDAgMDAzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEpD72UkkBlkN+ge6DITAvfncLg05JGClkKte0fhwXX2HUHeA8MreZa1SMiABv3bw+xZLPf3ZUAr6Rbrai/H9sSoRs+RZzQzAGN8dnoRbqzvmaBMNpLIFdE2HnGHPqqh5Qo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUCN6b39JES4tqzYcfk+/rlnmmJp0wHwYDVR0jBBgwFoAUb8VzvJ66ROWxzPC8KsU3unR8AdQwCgYIKoZIzj0EAwMDaAAwZQIwRwHU/rGpyktNgROIFP2/uuM9xsIWP6EO8EvBOkc0/U95AduXMwl6kHHxX8qPGYWNAjEAxaps4b0ovexhFbUpSUe/eLvxoP1S8adH9lkdJLSjJMDp+B/YfTQew60DJzMxYZZI</ds:X509Certificate><ds:X509Certificate>MIICOjCCAcGgAwIBAgIUQBY9MlCkUevj+yYa6C0Lzmc4YpgwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAeFw0yMzA1MTEwMDAwMDBaFw0zMzA1MTEyMzU5NTlaMFQxKDAmBgNVBAMMH05WSURJQSBSZWZlcmVuY2UgVmFsdWUgR0gxMDAgQ0ExGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATbokXf+6PBMDB8cYUztr9ZbuzFnKiMaVzB7BSVVPCGxi4TR60o3jigeLgxsTua5dA3tKvyt6nuWrZtiI+ibNFsIx5sUtuWHN9T6qACPp63+Wc08qnpmGUTkOrqnuFUkIGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRvxXO8nrpE5bHM8LwqxTe6dHwB1DAfBgNVHSMEGDAWgBQf5L2bUUtkgFR84VAklxpTMwKKJzAKBggqhkjOPQQDAwNnADBkAjBPVKiwgeVonJ3JDJd3re+cgDiloqiNuuTRYLwaMRubU25ZoFwO3EP0yOhf8+9Szg8CMDqgbk5+sJ5IGzpVS1qQqTnWHir8xvx0OKHmg8CLgbpBUIdD759OUcvVnliE7ihsnQ==</ds:X509Certificate><ds:X509Certificate>MIICLjCCAbSgAwIBAgIUc+13azQDRQFlzeZ6FNFuDmHxp0gwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAgFw0yMzAzMTYxNTM3MzRaGA8yMDUzMDMwODE1MzczNFowRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCVxTuS9lz2zaDBXySJTQvitTQ18Ev7/qbuV9pE3vaIBShXBvZPi15zK+uUbL7UX1U8dFxs/W9448Qz01J/BK6+/0tBBqENPFUUMLeLjimizRJxzzzeErJPT5AziesRDvaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFB/kvZtRS2SAVHzhUCSXGlMzAoonMB8GA1UdIwQYMBaAFB/kvZtRS2SAVHzhUCSXGlMzAoonMAoGCCqGSM49BAMDA2gAMGUCMQDwq2lsRdvK5JUNnYZinwYG2ENgxsJkWdHB+RXqmZC3HrjinNZtNz0/8UUdUGWFD3MCMAHOL+pJyRxG2rS40IjLQK/M+phPoXL01lh2aFhy/+iZCmR+bpquQVTcMTHlqeZ7dA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
"####;
const NV_EMPTY_VBIOS_RIM: &str = r####"<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns0="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ns2="http://www.w3.org/2001/04/xmlenc#sha384" corpus="false" name="GH100" patch="false" supplemental="false" tagId="7b76d44342795077b92b7ef5f1e8a97c0e56804312af879959d7fabac6bdb91eb82e43cdf42e5bf4fbd20c0b340657a4" version="1.0" tagVersion="0">
    <ns0:Entity name="NVIDIA Corporation" role="softwareCreator tagCreator"/>
    <ns0:Meta xmlns:ns1="https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/" colloquialVersion="96.00.9F.00.04" edition="GPU" product="GH100" revision="r1" PayloadType="direct" ns1:BindingSpec="RIMIM" ns1:BindingSpecVersion="1.01" ns1:PlatformManufacturerId="5703" ns1:PlatformManufacturerStr="NVIDIA Corporation" ns1:PlatformModel="GH100" ns1:FirmwareManufacturer="NVIDIA Corporation" ns1:FirmwareManufacturerId="5703"/>
    <ns0:Payload xmlns:SHA384="http://www.w3.org/2001/04/xmlenc#sha384">
        <ns0:Resource type="Measurement" index="1" active="False" alternatives="1" ns2:Hash0="2a95d33ea53b97ce5f837488a8ca44ecba88c8b8bef7eb1afae54fd24303b78544ad021067a9b9c658a5f3df5e464c0b" name="Measurement_1" size="48"/>
    </ns0:Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384"/><ds:DigestValue>+U0fTYxRRWAocErP+U1bcStEeZCGjimiScyqML0G90ICG2/H2zBgWhnwknvccgow</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>gQvTGUXD42ysWG2SPt9uSZk29H76IQdU2HCIJdcJeqYpxW4p0hRu6lbHcrOAdFhDEUL2fhZ51PbG9uT63o/z+ZG7C0GKfCYeIDMQWdF0GrrlkdDp28rcpNHZZEKq/YJ6</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICUzCCAdqgAwIBAgIUcdbjrGZa0/vHc5UkqiWsijIrzBswCgYIKoZIzj0EAwMwTDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTEsMCoGA1UEAwwjTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBMMyBHSDEwMCAwMDMwHhcNMjYwMzEyMjMzODEzWhcNMjgwMzExMjMzODEzWjBpMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRswGQYDVQQKDBJOVklESUEgQ29ycG9yYXRpb24xGjAYBgNVBAMMEUhDQyBSSU0gTDQgU2lnbmVyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE97yTAJrx9j/Ree0NffyNEqp9HjxYaTXe/I1zt4xcYDsBkW59Jg2RbmQDlZRLjIsUj1KnmzdaKHwV8XK52LFT8TezKLVruFHt+/qSXNSaWJiMUqkfwRvkxFnaunnZ2J3vo2AwXjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUUxewc+HYekLZRTVOtuB88qHZ8F4wHwYDVR0jBBgwFoAUCN6b39JES4tqzYcfk+/rlnmmJp0wCgYIKoZIzj0EAwMDZwAwZAIwGu4dcIcsvQHjB6vr2ET3WwAS6iULSNpkVVlAdrLysLLv/NhZerNs4X8+uyBm7TjEAjBnqNvNV/uimZ3TIrEYHdjlWuuesFW4VkCnSjgu+qIlM7fv9RWmpIzicbdPwj3WkHs=</ds:X509Certificate><ds:X509Certificate>MIICRTCCAcugAwIBAgIUWYZtwAiXMdj7MqzcsLOLUlixxRkwCgYIKoZIzj0EAwMwVDEoMCYGA1UEAwwfTlZJRElBIFJlZmVyZW5jZSBWYWx1ZSBHSDEwMCBDQTEbMBkGA1UECgwSTlZJRElBIENvcnBvcmF0aW9uMQswCQYDVQQGEwJVUzAeFw0yNTExMDcwMDAwMDBaFw0zNTExMDcyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZOVklESUExLDAqBgNVBAMMI05WSURJQSBSZWZlcmVuY2UgVmFsdWUgTDMgR0gxMDAgMDAzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEpD72UkkBlkN+ge6DITAvfncLg05JGClkKte0fhwXX2HUHeA8MreZa1SMiABv3bw+xZLPf3ZUAr6Rbrai/H9sSoRs+RZzQzAGN8dnoRbqzvmaBMNpLIFdE2HnGHPqqh5Qo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUCN6b39JES4tqzYcfk+/rlnmmJp0wHwYDVR0jBBgwFoAUb8VzvJ66ROWxzPC8KsU3unR8AdQwCgYIKoZIzj0EAwMDaAAwZQIwRwHU/rGpyktNgROIFP2/uuM9xsIWP6EO8EvBOkc0/U95AduXMwl6kHHxX8qPGYWNAjEAxaps4b0ovexhFbUpSUe/eLvxoP1S8adH9lkdJLSjJMDp+B/YfTQew60DJzMxYZZI</ds:X509Certificate><ds:X509Certificate>MIICOjCCAcGgAwIBAgIUQBY9MlCkUevj+yYa6C0Lzmc4YpgwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAeFw0yMzA1MTEwMDAwMDBaFw0zMzA1MTEyMzU5NTlaMFQxKDAmBgNVBAMMH05WSURJQSBSZWZlcmVuY2UgVmFsdWUgR0gxMDAgQ0ExGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATbokXf+6PBMDB8cYUztr9ZbuzFnKiMaVzB7BSVVPCGxi4TR60o3jigeLgxsTua5dA3tKvyt6nuWrZtiI+ibNFsIx5sUtuWHN9T6qACPp63+Wc08qnpmGUTkOrqnuFUkIGjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRvxXO8nrpE5bHM8LwqxTe6dHwB1DAfBgNVHSMEGDAWgBQf5L2bUUtkgFR84VAklxpTMwKKJzAKBggqhkjOPQQDAwNnADBkAjBPVKiwgeVonJ3JDJd3re+cgDiloqiNuuTRYLwaMRubU25ZoFwO3EP0yOhf8+9Szg8CMDqgbk5+sJ5IGzpVS1qQqTnWHir8xvx0OKHmg8CLgbpBUIdD759OUcvVnliE7ihsnQ==</ds:X509Certificate><ds:X509Certificate>MIICLjCCAbSgAwIBAgIUc+13azQDRQFlzeZ6FNFuDmHxp0gwCgYIKoZIzj0EAwMwRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTAgFw0yMzAzMTYxNTM3MzRaGA8yMDUzMDMwODE1MzczNFowRTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBk5WSURJQTElMCMGA1UEAwwcTlZJRElBIENvUklNIHNpZ25pbmcgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABCVxTuS9lz2zaDBXySJTQvitTQ18Ev7/qbuV9pE3vaIBShXBvZPi15zK+uUbL7UX1U8dFxs/W9448Qz01J/BK6+/0tBBqENPFUUMLeLjimizRJxzzzeErJPT5AziesRDvaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFB/kvZtRS2SAVHzhUCSXGlMzAoonMB8GA1UdIwQYMBaAFB/kvZtRS2SAVHzhUCSXGlMzAoonMAoGCCqGSM49BAMDA2gAMGUCMQDwq2lsRdvK5JUNnYZinwYG2ENgxsJkWdHB+RXqmZC3HrjinNZtNz0/8UUdUGWFD3MCMAHOL+pJyRxG2rS40IjLQK/M+phPoXL01lh2aFhy/+iZCmR+bpquQVTcMTHlqeZ7dA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
"####;
const NV_SHARED_KEY_CHAIN_PEM: &str = r####"-----BEGIN CERTIFICATE-----
MIIDezCCAwKgAwIBAgIUEVkaucCylvjLfAPIUf5hzZBghKIwCgYIKoZIzj0EAwMw
ZDEbMBkGA1UEBRMSNDFBOEVDNjU4Q0IwN0M0NEQyMQswCQYDVQQGEwJVUzEbMBkG
A1UECgwSTlZJRElBIENvcnBvcmF0aW9uMRswGQYDVQQDDBJHSDEwMCBBMDEgR1NQ
IEJST00wIBcNMjAxMDE3MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMHwxMTAvBgNV
BAUTKDZFRTZEQkE4MjBCNUY5NTM0NUQ3RkJGNjMyQjM2OUI1MDBDOEM2MEExCzAJ
BgNVBAYTAlVTMRswGQYDVQQKDBJOVklESUEgQ29ycG9yYXRpb24xHTAbBgNVBAMM
FEdIMTAwIEEwMSBHU1AgRk1DIExGMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEcGHt
OH8DYeappr8LXV79VN/kBM8JG/OO1eOC7lO24W+9CXYj3LtlDgDCw+j22U34Il/g
bTYVBpRZchX9J9Xmb3Y1mk8m7hWaU/F9nOWCdzyQCBmcxsBUkOis1oogQLCio4IB
WTCCAVUwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBTuocMcg8uVFclIjtWalxek
ta1pOTAfBgNVHSMEGDAWgBS5WcjHV69tJ4z/W/mQcuXvFzl+UjA4BgNVHREEMTAv
oC0GCisGAQQBgxyCEgGgHwwdTlZJRElBOkdIMTAwOjQ4QjAyREExQkRGN0E5REUw
gcgGBmeBBQUEAQSBvTCBugSBt2/siJVm/6YiHE/7l49dGfy53Sh9AKFRwSUW42bY
SocvcMZwYhVK69BGmtSBkdZyMcoj2J31R9kB0tXQUvCKVXLQxZpnRlMuePjpzktf
HWNXiMQvinS6LmvliMSvw0+b8lYovovPy1JBQ4aI2czfQl2hD2JKRhVhGCNnx60F
S2GhE2LXGNzjFvCra4U475s2btiGV1i7YAZ9doZhbjn0uh8EbB9/qcRrSsZSrWbT
09d1Hl5tluW85TAKBggqhkjOPQQDAwNnADBkAjAoX42ocRHKlUZWJSOKvHmoHvrP
hGbVSmnlUv1nxoq2z5jYmAK9ChGHhJXUVip1WiMCMAeRAFbI/6Wtc7OvjKUfEZRH
3lpRSz/sVPzf+gRNQnjkXXwSeb2gv/FsLsio7j1hCg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICXDCCAeGgAwIBAgIULXY9kloNTBHXfL3qV9JKcR6uzI0wCgYIKoZIzj0EAwMw
UzEnMCUGA1UEAwweTlZJRElBIEdIMTAwIFByb3Zpc2lvbmVyIElDQSAxMRswGQYD
VQQKDBJOVklESUEgQ29ycG9yYXRpb24xCzAJBgNVBAYTAlVTMCAXDTIwMTAxNzAw
MDAwMFoYDzk5OTkxMjMxMjM1OTU5WjBkMRswGQYDVQQFExI0MUE4RUM2NThDQjA3
QzQ0RDIxCzAJBgNVBAYTAlVTMRswGQYDVQQKDBJOVklESUEgQ29ycG9yYXRpb24x
GzAZBgNVBAMMEkdIMTAwIEEwMSBHU1AgQlJPTTB2MBAGByqGSM49AgEGBSuBBAAi
A2IABDfyk42c1+xmbCJge55lPlD3NXBtTU9dLl/ZavTBr5TFF5Rcs69hYPQQKyHN
tJjUDnjiw1leAk73y/SKSQb2tDATiuEm5DyoLvnGRieBrAUTjUQfYH3NDn5tNtKV
YMTo4qNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0O
BBYEFLlZyMdXr20njP9b+ZBy5e8XOX5SMB8GA1UdIwQYMBaAFCKYJYzZIrGQrTNu
PwUFWWmzdW2sMAoGCCqGSM49BAMDA2kAMGYCMQClg4HGSjXsRwU2t4swnVp3zOg2
5xwtbVoos0wfVmDD1tPljrtyAP7mZKH9gM7uPlsCMQDvo0DLbLCDVKWFuPwjZ7Tk
xIeEmEXNZpKfhft5lBgbo0ad83Zz1b84yJ+iIz6/+Es=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICrjCCAjOgAwIBAgIUf8bLnHNCX2R1qH1hrKWSUbXYXIYwCgYIKoZIzj0EAwMw
PTEeMBwGA1UEAwwVTlZJRElBIEdIMTAwIElkZW50aXR5MRswGQYDVQQKDBJOVklE
SUEgQ29ycG9yYXRpb24wIBcNMjIwMzAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTla
MFMxJzAlBgNVBAMMHk5WSURJQSBHSDEwMCBQcm92aXNpb25lciBJQ0EgMTEbMBkG
A1UECgwSTlZJRElBIENvcnBvcmF0aW9uMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABB/v4pPIxY9HzhJZi5oywslM4tvRYgJfhyPDs2gPIpDW1VKn
E52ijyGPkry7fAKomKU6uKVbvz3rNSv1WCM83Sb4zYtKePJ73373TV21OdIwuNEP
nLXtVEtEsTOI+Q4oA6OB2zCB2DAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwICBDA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3JsLm5kaXMubnZpZGlhLmNv
bS9jcmwvbDItZ2gxMDAuY3JsMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYb
aHR0cDovL29jc3AubmRpcy5udmlkaWEuY29tMB0GA1UdDgQWBBQimCWM2SKxkK0z
bj8FBVlps3VtrDAfBgNVHSMEGDAWgBRrdbVxgw4NXi19Pc79+tfwFjpJwzAKBggq
hkjOPQQDAwNpADBmAjEAt4JNHkvNmD1WUnvqhB4vFViTwc1pFaIEPOQ15WtAZ3cL
R45xXgkBu+2qbsL2xyX1AjEAwztXYEw09TvYNuWypRQ0dXFZuse+jq5oYJAxBNcx
PU/u4Ct2+Ri/emLfI3Y3achC
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjzCCAhSgAwIBAgIUWP5UAvwi4jC7PwgQedYHsPzAmmswCgYIKoZIzj0EAwMw
NTEiMCAGA1UEAwwZTlZJRElBIERldmljZSBJZGVudGl0eSBDQTEPMA0GA1UECgwG
TlZJRElBMCAXDTIyMDExMjAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA9MR4wHAYD
VQQDDBVOVklESUEgR0gxMDAgSWRlbnRpdHkxGzAZBgNVBAoMEk5WSURJQSBDb3Jw
b3JhdGlvbjB2MBAGByqGSM49AgEGBSuBBAAiA2IABOvMjzkMsZVZ7gykxNleV3PX
JoLv8RU9YJGckR+KEg3MWmRrs+CITG1+O6hwFFtD/Ax09WAnqtmkRGUbcZRwWVQU
rvS5PpVZnN0qT9UhyAU/BY95kH1nDWzrdqM+cyb6tqOB2jCB1zAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwICBDA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8v
Y3JsLm5kaXMubnZpZGlhLmNvbS9jcmwvbDEtcm9vdC5jcmwwNwYIKwYBBQUHAQEE
KzApMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5uZGlzLm52aWRpYS5jb20wHQYD
VR0OBBYEFGt1tXGDDg1eLX09zv361/AWOknDMB8GA1UdIwQYMBaAFGt1tXGDDg1e
LX09zv361/AWOknDMAoGCCqGSM49BAMDA2kAMGYCMQCXfERrtwZLAIaakYCrV3HG
tFl6XUke/dr0Qy73py+3TY45G/DpFn6q+RREbvO6WkQCMQCqCJ7oNN90iHC6GBI0
F+P2ahMgalnxrn73DMUarJPso/InF8Ob1EtOQM7uuzZkIHA=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICDjCCAZSgAwIBAgIUL5A4Z/V0R1fAQbEmBZqkY3tSQyEwCgYIKoZIzj0EAwMw
NTEiMCAGA1UEAwwZTlZJRElBIERldmljZSBJZGVudGl0eSBDQTEPMA0GA1UECgwG
TlZJRElBMCAXDTIxMTEwNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA1MSIwIAYD
VQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklESUEw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAATrzI85DLGVWe4MpMTZXldz1yaC7/EVPWCR
nJEfihINzFpka7PgiExtfjuocBRbQ/wMdPVgJ6rZpERlG3GUcFlUFK70uT6VWZzd
Kk/VIcgFPwWPeZB9Zw1s63ajPnMm+rajYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRrdbVxgw4NXi19Pc79+tfwFjpJwzAfBgNV
HSMEGDAWgBRrdbVxgw4NXi19Pc79+tfwFjpJwzAKBggqhkjOPQQDAwNoADBlAjAF
cw638CcsDIVQKH3R1Af73o64f4bQzjo1Bcw4Nm0Nf06K/eQl6NgJhz7V+u3c0j0C
MQCyxQx90b2C0q7GZbv/Ng5/af09j0GOUyJRQhxTgt+jVXkoN3AeMoITC8iBSqd5
zQQ=
-----END CERTIFICATE-----
"####;
const NV_SHARED_KEY_CRLS: [&str; 2] = ["MIIBTTCB1AIBATAKBggqhkjOPQQDAjA9MR4wHAYDVQQDDBVOVklESUEgR0gxMDAgSWRlbnRpdHkxGzAZBgNVBAoMEk5WSURJQSBDb3Jwb3JhdGlvbhcNMjYwMTE2MjEwNjExWhcNMjgwMTE2MjEwNjExWjA1MDMCFH/Gy5xzQl9kdah9YaylklG12FyGFw0yNjAxMTYyMTA2MTFaMAwwCgYDVR0VBAMKAQGgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFGt1tXGDDg1eLX09zv361/AWOknDMAoGCCqGSM49BAMCA2gAMGUCMFNaUdoveWMVaWkCqmF92WXAxuxwXx0dmm+cwyMczqerDAoy6n4jLlDNCIdS0d0yBgIxAPbmDprzK+ltv6ZFf4JRitch3XQ2ea9dKMqCrZ7BPxWuiOcYTMPa8TjGPU5nA04GtQ==", "MIIBDTCBlQIBATAKBggqhkjOPQQDAjA1MSIwIAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklESUEXDTI2MDExNjIxMDYxMVoXDTI4MDExNjIxMDYxMVqgLzAtMAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFGt1tXGDDg1eLX09zv361/AWOknDMAoGCCqGSM49BAMCA2cAMGQCME2cEXE3RqTXQaQfpo2Zq9kT0/CZeWw5+l/YVyp6KNlNp9/Hfkw4oChtYZHK1plMEwIwN/17Wa8glXJ7NHYM+TbvCoTQEV2VFrHAhZDx701XqZNz4VP1xvdiPMyCWP/OmAZ8"];
const TSA_ROOT_JSON: &str = r####"{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","tlogs":[{"baseUrl":"https://synthetic.log","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnPkV8lzWQc0ypRkbZMrgzto5ywKV//wysr4u3qEiwNLE/GAovI+3I6faTgkvXhennaeyXQy2r+yQYF/A6N/zog==","keyDetails":"PKIX_ECDSA_P256_SHA_256","validFor":{"start":"2025-01-01T00:00:00.000Z"}},"logId":{"keyId":"GooqiGd3DcU1H/uiluyHsn7mCdyR/cFeK0/NUAabdfg="}},{"baseUrl":"https://log2.synthetic.example","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":"MCowBQYDK2VwAyEAsB4gsWnm+VJFgSo5rg5lF3dqguH5ER7S8kTaccTgzQw=","keyDetails":"PKIX_ED25519","validFor":{"start":"2025-01-01T00:00:00.000Z"}},"logId":{"keyId":"JukvyH4el8Fwn+gYe+Wh7OqqM8i9tVKPxNDJnU0x+PI="}}],"certificateAuthorities":[{"subject":{"organization":"pca-synthetic","commonName":"pca-synthetic-intermediate"},"uri":"https://synthetic.ca","certChain":{"certificates":[{"rawBytes":"MIIBxDCCAWqgAwIBAgIBAjAKBggqhkjOPQQDAjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA9MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMSMwIQYDVQQDDBpwY2Etc3ludGhldGljLWludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIi0GUdJoQ9ycmoP7DZnlcUw/vHwT4IPBXmBaB8vHqbMBf/q3sgciG/8lIF26UEtM79KmBAbOEbHcPWWELzEucSjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRg84o6genikBUDWhjfRnxHAuUE8TAfBgNVHSMEGDAWgBR6KVspkg+8HLKeug6J2jl6ndA9ETAKBggqhkjOPQQDAgNIADBFAiEAnvKZ0p3xoY3x8eZsffYwch0lb7ilqjhrOHsXRvYk/NkCIAikJhTIqN8kDlRCZL0b0CBUrO1Fy9pl+PuM8klQBH+E"},{"rawBytes":"MIIBvDCCAWKgAwIBAgIBATAKBggqhkjOPQQDAjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQyCTyTRSkNKM6Ylu8P1v/sJgSz91fyQzxhhUNAkxHuyIz+tNZd1+VzOENf8sNtRBdefDkWHM5v+aLRJSfCpVW+o2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUeilbKZIPvByynroOido5ep3QPREwHwYDVR0jBBgwFoAUeilbKZIPvByynroOido5ep3QPREwCgYIKoZIzj0EAwIDSAAwRQIhAI3WTTWFHW9jsgVbG4GXo13HAG9P5AH5A4BUDshrVaVOAiBtIw5zwYrPzP4rhUqrorLblI6/w4iHo4R4PWzPYIhwgA=="}]},"validFor":{"start":"2025-01-01T00:00:00.000Z"}}],"ctlogs":[{"baseUrl":"https://synthetic.ct","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmy1ZETJoSiScYTcQUC5AyrklHc35doCKkr7VUJ2eX0TPmpLBukzEFgfGkEIZyxs9GaE0e98rO0v3LVdCV58+cA==","keyDetails":"PKIX_ECDSA_P256_SHA_256","validFor":{"start":"2025-01-01T00:00:00.000Z"}},"logId":{"keyId":"KNNlFF7VvTd0jbjzvOEqkMTZZK/XZOL0JnlPMCiMJ/o="}}],"timestampAuthorities":[{"subject":{"organization":"pca-synthetic","commonName":"pca-synthetic-tsa"},"uri":"https://synthetic.tsa","certChain":{"certificates":[{"rawBytes":"MIIBwTCCAWigAwIBAgIBAzAKBggqhkjOPQQDAjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA0MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRowGAYDVQQDDBFwY2Etc3ludGhldGljLXRzYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHCIdKYtFQHUnIcjcHg/YUJP3QiEYyg3Fr+lVehjEzegBj4U502itBe+RmCACMxS1TXGc++cddlhPamhtbYNSGijajBoMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUk+QAHGYqNm9Ei+/B9ptV5gD2hZEwHwYDVR0jBBgwFoAUeilbKZIPvByynroOido5ep3QPREwCgYIKoZIzj0EAwIDRwAwRAIgC1h84295vjoHNmTG8hdQduXRzQdryjIFwmCXv0LPOIkCIHrGFEdmaKFvmHGLMIstdhiReJxqGOqtUlYzpMwRqlW2"},{"rawBytes":"MIIBvDCCAWKgAwIBAgIBATAKBggqhkjOPQQDAjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQyCTyTRSkNKM6Ylu8P1v/sJgSz91fyQzxhhUNAkxHuyIz+tNZd1+VzOENf8sNtRBdefDkWHM5v+aLRJSfCpVW+o2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUeilbKZIPvByynroOido5ep3QPREwHwYDVR0jBBgwFoAUeilbKZIPvByynroOido5ep3QPREwCgYIKoZIzj0EAwIDSAAwRQIhAI3WTTWFHW9jsgVbG4GXo13HAG9P5AH5A4BUDshrVaVOAiBtIw5zwYrPzP4rhUqrorLblI6/w4iHo4R4PWzPYIhwgA=="}]},"validFor":{"start":"2025-01-01T00:00:00.000Z"}}]}"####;
const TSA_BUNDLE_JSON: &str = r####"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"MIIDVTCCAv2gAwIBAgIBZDAKBggqhkjOPQQDAjA9MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMSMwIQYDVQQDDBpwY2Etc3ludGhldGljLWludGVybWVkaWF0ZTAeFw0yNjA2MDExMTU5MDBaFw0yNjA2MDExMjEwMDBaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASUJ/jHwRA39198Lch+NCMxK+b8qNAFn5Q/dqbGe7Smn7fOMeZSGP3qkuhOzzgj4SO1ONA6bPaqocE9EFB8xNQWo4ICKTCCAiUwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBTSPfqNSD6Dqil0UPWy2Yj9geSR0zAfBgNVHSMEGDAWgBRg84o6genikBUDWhjfRnxHAuUE8TBiBgNVHREBAf8EWDBWhlRodHRwczovL2dpdGh1Yi5jb20vcGNhLXN5bnRoZXRpYy90b29sLy5naXRodWIvd29ya2Zsb3dzL3JlbGVhc2UueW1sQHJlZnMvdGFncy92MS4wLjAwOwYKKwYBBAGDvzABCAQtDCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tMDUGCisGAQQBg78wAQwEJwwlaHR0cHM6Ly9naXRodWIuY29tL3BjYS1zeW50aGV0aWMvdG9vbDA4BgorBgEEAYO/MAENBCoMKGFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEwIAYKKwYBBAGDvzABDgQSDBByZWZzL3RhZ3MvdjEuMC4wMIGJBgorBgEEAdZ5AgQCBHsEeQB3AHUAKNNlFF7VvTd0jbjzvOEqkMTZZK/XZOL0JnlPMCiMJ/oAAAGegw2k0AAABAMARjBEAiAyDUmF/8zpYy3bvFYK0nUJYeqzaWFja2FbaGghlBJdOgIgAzUsWkbcsk9eBYT9z27P3n6sMgxSMx2wBJtiCL9pD+swCgYIKoZIzj0EAwIDRgAwQwIfQbiauwRShebXWexnakHeMexi3NjicZ6Y/+yFxTRFBwIgMmj3ic+x1DROpfNUOtU1M0+yWbxZNWlm3ecWgLMEUQY="},"tlogEntries":[{"logIndex":"5","logId":{"keyId":"GooqiGd3DcU1H/uiluyHsn7mCdyR/cFeK0/NUAabdfg="},"kindVersion":{"kind":"dsse","version":"0.0.1"},"integratedTime":"1780315260","inclusionPromise":{"signedEntryTimestamp":"MEQCIAg2dmfjx0glhAcRhVKsueY18B7DSP3KSiQUIXCPlS+VAiAxvFsv15/PzdsxCo1TGuiWcczWJL2UkEZaal1l0kSQ0Q=="},"inclusionProof":{"logIndex":"5","rootHash":"kDMJKhfR39ADraIFe/h7h40fYdGjQ/QHr9zuUtI+kT0=","treeSize":"7","hashes":["B8P59YsxMvXzk+995Cit88sj0MVTiDGotnXehxxf/Mc=","g/ViqC8MPC5ONSYVfmz6tloU/uc4yPBI9JCap7VLVqE=","XIVQJIkhSBsgX8ZpE1MyyCQU4eSLEyKazRpI0096JWk="],"checkpoint":{"envelope":"synthetic.log - 1\n7\nkDMJKhfR39ADraIFe/h7h40fYdGjQ/QHr9zuUtI+kT0=\n\n\u2014 synthetic.log GooqiDBFAiEA2LxO+l/SNg/OWttUg4+L3QscYLKczFQijM8TGwtzNYUCIEnHpdKNC68IWQvC1nBOgETb/VBDeyLdTdwBxWU6TDRD\n"}},"canonicalizedBody":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiZHNzZSIsInNwZWMiOnsiZW52ZWxvcGVIYXNoIjp7ImFsZ29yaXRobSI6InNoYTI1NiIsInZhbHVlIjoiNGM1MDNjYTY3NzYxZTVjNGFhZWNmZTk5NjI0NGMyNWQ4YzBiNDA5MDJkMTA4NWM4NWI0NDY4YmQ1Njc1NDhjNiJ9LCJwYXlsb2FkSGFzaCI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjBiNDI4MWYwMTI3OWIzMTFlNTQ5MDUxMTM5NDczNjEzNTRlNGQyMDc0YTgyZTUyMGE0MmI0MjBhN2FlYjcxMDUifSwic2lnbmF0dXJlcyI6W3sic2lnbmF0dXJlIjoiTUVRQ0lEOTZSbi8zWGxmdDBEZ2JSblR6OTBmZm1tbGx1d2hHV3dBNE9PejFGMUh4QWlBd1hYSnhTaXB0NGFwY0pSM1FhNlZaTGJ3dndheFg4N2pSMWJBaDl0VGs5dz09IiwidmVyaWZpZXIiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VSV1ZFTkRRWFl5WjBGM1NVSkJaMGxDV2tSQlMwSm5aM0ZvYTJwUFVGRlJSRUZxUVRsTlVsbDNSa0ZaUkZaUlVVdEVRVEYzV1RKRmRHTXpiSFVLWkVkb2JHUkhiR3BOVTAxM1NWRlpSRlpSVVVSRVFuQjNXVEpGZEdNemJIVmtSMmhzWkVkc2FreFhiSFZrUjFaNVlsZFdhMkZYUmpCYVZFRmxSbmN3ZVFwT2FrRXlUVVJGZUUxVVZUVk5SRUpoUm5jd2VVNXFRVEpOUkVWNFRXcEZkMDFFUW1GTlFVRjNWMVJCVkVKblkzRm9hMnBQVUZGSlFrSm5aM0ZvYTJwUENsQlJUVUpDZDA1RFFVRlRWVW92YWtoM1VrRXpPVEU1T0V4amFDdE9RMDE0U3l0aU9IRk9RVVp1TlZFdlpIRmlSMlUzVTIxdU4yWlBUV1ZhVTBkUU0zRUthM1ZvVDNwNloybzBVMDh4VDA1Qk5tSlFZWEZ2WTBVNVJVWkNPSGhPVVZkdk5FbERTMVJEUTBGcFZYZEVaMWxFVmxJd1VFRlJTQzlDUVZGRVFXZGxRUXBOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVJd1IwRXhWV1JFWjFGWFFrSlVVMUJtY1U1VFJEWkVjV2xzTUZWUVYza3lXV281Q21kbFUxSXdla0ZtUW1kT1ZraFRUVVZIUkVGWFowSlNaemcwYnpablpXNXBhMEpWUkZkb2FtWlNibmhJUVhWVlJUaFVRbWxDWjA1V1NGSkZRa0ZtT0VVS1YwUkNWMmhzVW05a1NGSjNZM3B2ZGt3eVpIQmtSMmd4V1drMWFtSXlNSFpqUjA1b1RGaE9OV0p1VW05YVdGSndXWGs1TUdJeU9YTk1lVFZ1WVZoU2J3cGtWMGwyWkRJNWVXRXlXbk5pTTJSNlRETktiR0pIVm1oak1sVjFaVmN4YzFGSVNteGFiazEyWkVkR2JtTjVPVEpOVXpSM1RHcEJkMDkzV1V0TGQxbENDa0pCUjBSMmVrRkNRMEZSZEVSRGRHOWtTRkozWTNwdmRrd3pVblpoTWxaMVRHMUdhbVJIYkhaaWJrMTFXakpzTUdGSVZtbGtXRTVzWTIxT2RtSnVVbXdLWW01UmRWa3lPWFJOUkZWSFEybHpSMEZSVVVKbk56aDNRVkYzUlVwM2QyeGhTRkl3WTBoTk5reDVPVzVoV0ZKdlpGZEpkVmt5T1hSTU0wSnFXVk14ZWdwbFZ6VXdZVWRXTUdGWFRYWmtSemwyWWtSQk5FSm5iM0pDWjBWRlFWbFBMMDFCUlU1Q1EyOU5TMGRHYUZsWFJtaFpWMFpvV1ZkR2FGbFhSbWhaVjBab0NsbFhSbWhaVjBab1dWZEdhRmxYUm1oWlYwWm9XVmRHYUZsWFJtaFpWMFYzU1VGWlMwdDNXVUpDUVVkRWRucEJRa1JuVVZORVFrSjVXbGRhZWt3elVtZ0tXak5OZG1ScVJYVk5RelIzVFVsSFNrSm5iM0pDWjBWRlFXUmFOVUZuVVVOQ1NITkZaVkZDTTBGSVZVRkxUazVzUmtZM1ZuWlVaREJxWW1wNmRrOUZjUXByVFZSYVdrc3ZXRnBQVERCS2JteFFUVU5wVFVvdmIwRkJRVWRsWjNjeWF6QkJRVUZDUVUxQlVtcENSVUZwUVhsRVZXMUdMemg2Y0ZsNU0ySjJSbGxMQ2pCdVZVcFpaWEY2WVZkR2FtRXlSbUpoUjJkb2JFSktaRTluU1dkQmVsVnpWMnRpWTNOck9XVkNXVlE1ZWpJM1VETnVObk5OWjNoVFRYZ3lkMEpLZEdrS1EwdzVjRVFyYzNkRFoxbEpTMjlhU1hwcU1FVkJkMGxFVW1kQmQxRjNTV1pSWW1saGRYZFNVMmhsWWxoWFpYaHVZV3RJWlUxbGVHa3pUbXBwWTFvMldRb3ZLM2xHZUZSU1JrSjNTV2ROYldvemFXTXJlREZFVWs5d1prNVZUM1JWTVUwd0szbFhZbmhhVGxkc2JUTmxZMWRuVEUxRlZWRlpQUW90TFMwdExVVk9SQ0JEUlZKVVNVWkpRMEZVUlMwdExTMHRDZz09In1dfX0="}],"timestampVerificationData":{"rfc3161Timestamps":[{"signedTimestamp":"MIIBjDADAgEAMIIBgwYJKoZIhvcNAQcCoIIBdDCCAXACAQMxDTALBglghkgBZQMEAgEwZwYLKoZIhvcNAQkQAQSgWARWMFQCAQEGCisGAQQBg78wYwEwLzALBglghkgBZQMEAgEEIBB5BUPQXRRG4hTZHInnvfHfUN4WMGHPPmt9VZSTRyEHAgEHGA8yMDI2MDYwMTEyMDAzMFoxgfIwge8CAQEwOjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QCAQMwCwYJYIZIAWUDBAIBoE0wGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCfgxUfVlT8uLyr1qQ/pBlKYJcJQMp+zWwLk1k+Ay5NzTAKBggqhkjOPQQDAgRGMEQCIGNexK1YZzZ+BKInyCpxrJMUldH3Ly2+YVAweGwJeNmXAiBoNovLR0c8Q0Gy9qNjf8Hcdk4o5iuOhWk30bjYk6IxlA=="}]}},"dsseEnvelope":{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCJzdWJqZWN0IjpbeyJuYW1lIjoidG9vbC50YXIiLCJkaWdlc3QiOnsic2hhMjU2IjoiOTRmNWI3ZmEzNTA0YzU2OWJlMTFiZjhmMmRiZWFmZmVmZWVlYjM4ZmY0OTg1NGMxMjMyN2ViOGMwNTU5ZjEwOSJ9fV0sInByZWRpY2F0ZVR5cGUiOiJodHRwczovL3Nsc2EuZGV2L3Byb3ZlbmFuY2UvdjEiLCJwcmVkaWNhdGUiOnsiYnVpbGREZWZpbml0aW9uIjp7ImJ1aWxkVHlwZSI6Imh0dHBzOi8vYWN0aW9ucy5naXRodWIuaW8vYnVpbGR0eXBlcy93b3JrZmxvdy92MSIsImV4dGVybmFsUGFyYW1ldGVycyI6eyJ3b3JrZmxvdyI6eyJyZWYiOiJyZWZzL3RhZ3MvdjEuMC4wIiwicmVwb3NpdG9yeSI6Imh0dHBzOi8vZ2l0aHViLmNvbS9wY2Etc3ludGhldGljL3Rvb2wiLCJwYXRoIjoiLmdpdGh1Yi93b3JrZmxvd3MvcmVsZWFzZS55bWwifX0sInJlc29sdmVkRGVwZW5kZW5jaWVzIjpbeyJ1cmkiOiJnaXQraHR0cHM6Ly9naXRodWIuY29tL3BjYS1zeW50aGV0aWMvdG9vbEByZWZzL3RhZ3MvdjEuMC4wIiwiZGlnZXN0Ijp7ImdpdENvbW1pdCI6ImFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEifX1dfSwicnVuRGV0YWlscyI6eyJidWlsZGVyIjp7ImlkIjoiaHR0cHM6Ly9naXRodWIuY29tL2FjdGlvbnMvcnVubmVyL2dpdGh1Yi1ob3N0ZWQifX19fQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEQCID96Rn/3Xlft0DgbRnTz90ffmmlluwhGWwA4OOz1F1HxAiAwXXJxSipt4apcJR3Qa6VZLbwvwaxX87jR1bAh9tTk9w==","keyid":""}]}}"####;
const TSA_CERT_EKU_NOT_OCTET: &str = "MIIBwjCCAWigAwIBAgIBAzAKBggqhkjOPQQDAjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA0MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRowGAYDVQQDDBFwY2Etc3ludGhldGljLXRzYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHCIdKYtFQHUnIcjcHg/YUJP3QiEYyg3Fr+lVehjEzegBj4U502itBe+RmCACMxS1TXGc++cddlhPamhtbYNSGijajBoMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8MDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUk+QAHGYqNm9Ei+/B9ptV5gD2hZEwHwYDVR0jBBgwFoAUeilbKZIPvByynroOido5ep3QPREwCgYIKoZIzj0EAwIDSAAwRQIhAOktMNdYsSjTgjXpZox+6KltQuF6M+P5mOXjvP2kLq5OAiB7WZ2+zYNv87BDMs3Qt5SccjuQtndcKGS9aO4UYmzyzg==";
const TSA_CERT_EXTS_NOT_SEQUENCE: &str = "MIIBwTCCAWigAwIBAgIBAzAKBggqhkjOPQQDAjA1MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRswGQYDVQQDDBJwY2Etc3ludGhldGljLXJvb3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA0MRYwFAYDVQQKDA1wY2Etc3ludGhldGljMRowGAYDVQQDDBFwY2Etc3ludGhldGljLXRzYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHCIdKYtFQHUnIcjcHg/YUJP3QiEYyg3Fr+lVehjEzegBj4U502itBe+RmCACMxS1TXGc++cddlhPamhtbYNSGijajFoMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUk+QAHGYqNm9Ei+/B9ptV5gD2hZEwHwYDVR0jBBgwFoAUeilbKZIPvByynroOido5ep3QPREwCgYIKoZIzj0EAwIDRwAwRAIgRsuGVPCs0yvW5vYIKvAo+1eWMa/GzAa14LPalkbskmoCID+8lAtOVWIVH4kh1WFGIKk0JuZjPveOJTmW4XuLhAxE";
const WF_LOOKUP: &str = r####"{"v":1,"wf":"lIlpHajms-20AWzyA2trgX9wmX7n-oDAPb9tReUOeIg","step":"lookup","seq":0,"prev":null,"outcome":"ok","params_digest":"vBYHInoMCc1qBtNIStEqCveXarPfAfvZR_p6MQJpigQ","outputs":{"refund_cents":{"digest":"07WwyvhB3Qs7tI76wYD2_sRowOrbCZob6YXtR55i7BI","num":2500,"unit":"usd_c","labels":[]},"order":{"digest":"d9VZNDrKt5q_NfrGz0r_AolN-k2izwa6yr6ji9faquU","num":null,"unit":null,"labels":[]},"email":{"digest":"PR7EY2AZq_h8qm4DxlrHAIJ5nkjSsPhC9I32mU1O_Dg","num":null,"unit":null,"labels":[]}},"issued_at":1799999970000,"signer":"6yzxO_euOl9hQWih-wknLTl3HsS4UjcngV5GbK-O4WM","sig":"gruQXZ4ktlr9SYljOhwbuxgA79H1cPqC0hr6HG_VzH4gDSebjT-mm7Lkpt3Gjt8CXUkIcajbQ41T2ZRiESIvAQ"}"####;
const WF_LOOKUP_AGAIN: &str = r####"{"v":1,"wf":"lIlpHajms-20AWzyA2trgX9wmX7n-oDAPb9tReUOeIg","step":"lookup","seq":1,"prev":"JkbyKX2UEhdA7yGJdfryjCon95AZX9LAukCukHf71ps","outcome":"ok","params_digest":"vBYHInoMCc1qBtNIStEqCveXarPfAfvZR_p6MQJpigQ","outputs":{"refund_cents":{"digest":"07WwyvhB3Qs7tI76wYD2_sRowOrbCZob6YXtR55i7BI","num":2500,"unit":"usd_c","labels":[]},"order":{"digest":"d9VZNDrKt5q_NfrGz0r_AolN-k2izwa6yr6ji9faquU","num":null,"unit":null,"labels":[]},"email":{"digest":"PR7EY2AZq_h8qm4DxlrHAIJ5nkjSsPhC9I32mU1O_Dg","num":null,"unit":null,"labels":[]}},"issued_at":1799999970500,"signer":"6yzxO_euOl9hQWih-wknLTl3HsS4UjcngV5GbK-O4WM","sig":"uD2gkfqpn6npMfLyJPetaQjvI1ZDKatNdskIt2NCNZJXOcRPNcLpF-2U2J0DDHIJ-GKntC_0AEXRsKlFWamWDA"}"####;
const WF_REFUND_SECRET_CONFIRMATION: &str = r####"{"v":1,"wf":"lIlpHajms-20AWzyA2trgX9wmX7n-oDAPb9tReUOeIg","step":"refund","seq":1,"prev":"JkbyKX2UEhdA7yGJdfryjCon95AZX9LAukCukHf71ps","outcome":"ok","params_digest":"_YpD9TUUuCBTlCJBkWRxl8RMM7EJFaqeg5gK8mb2oBE","outputs":{"confirmation":{"digest":"Evf7F9o2dnLAME8CC6Tym4dtCUxR8ygYnbVWfCzudLI","num":null,"unit":null,"labels":["secret"]},"id":{"digest":"16FjKrAUySeJGfQBzJdPDePVkrmw0JicAjviX1AkEhs","num":null,"unit":null,"labels":[]}},"issued_at":1799999971000,"signer":"6yzxO_euOl9hQWih-wknLTl3HsS4UjcngV5GbK-O4WM","sig":"mmtX9Ko91mZthEdZeRzthZhxsI4XDM1onOlV9qcb9nNbAPt8ExzTe5LQwslsDyV6pCTk5PROQNcmU_h0s9YkDg"}"####;
const WF_REFUND_CLEAN: &str = r####"{"v":1,"wf":"lIlpHajms-20AWzyA2trgX9wmX7n-oDAPb9tReUOeIg","step":"refund","seq":1,"prev":"JkbyKX2UEhdA7yGJdfryjCon95AZX9LAukCukHf71ps","outcome":"ok","params_digest":"_YpD9TUUuCBTlCJBkWRxl8RMM7EJFaqeg5gK8mb2oBE","outputs":{"confirmation":{"digest":"Evf7F9o2dnLAME8CC6Tym4dtCUxR8ygYnbVWfCzudLI","num":null,"unit":null,"labels":[]},"id":{"digest":"16FjKrAUySeJGfQBzJdPDePVkrmw0JicAjviX1AkEhs","num":null,"unit":null,"labels":[]}},"issued_at":1799999971000,"signer":"6yzxO_euOl9hQWih-wknLTl3HsS4UjcngV5GbK-O4WM","sig":"ecJCfUCVulKUvWjv6uFuXrCCHYuaeQ-BtTyC-YKKW_mk9sgHzVbI3x382p_Bnjfs4LyS1GR3v-pRDrhbVG86Aw"}"####;
const WF_REQ_REFUND: &str = r####"{"step":"refund","verb":"payments.refund","resource":"payments/42","params":{"amount":2500,"order":"ord_42"},"units":{"amount":"usd_c"},"goal_digest":"XbJFM98XeNwA_IViaror9sHJwl2-Aj561oSV6bp9z6Q","plan_root":"rHO1a5SdwC1SDyEAxLCsp681vmlzWD2IQkMoJp97eOo"}"####;
const WF_REQ_NOTIFY: &str = r####"{"step":"notify","verb":"mail.send","resource":"mail/out","params":{"ref":"conf_9"},"units":{},"goal_digest":"XbJFM98XeNwA_IViaror9sHJwl2-Aj561oSV6bp9z6Q","plan_root":"rHO1a5SdwC1SDyEAxLCsp681vmlzWD2IQkMoJp97eOo"}"####;
