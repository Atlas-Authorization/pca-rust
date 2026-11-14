//! Kill tests (group g3) from the 0.5 full mutation run: Intel DCAP quote / SGX extension / PCK chain / CRL parsing, the
//! Executor's late re-check, the KV operation store's corrupt record, the SQLite once-prune, intent-v2 model rules,
//! `fold_v2_reasons` and the approval render flattening.
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use atlas_pca::attest::dcap::{extract_pck_fmspc_and_tcb, parse_dcap_quote, verify_crl, verify_genuine_tdx_quote, verify_intel_pck_chain, DcapPolicy};
use atlas_pca::attest::x509::{der_wrap as w, Cert, EcCurve, PubKey};
use atlas_pca::*;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------------------------------------------------
// X.509 / DCAP builders: every certificate and signature below is real.

const NOW: f64 = 1.8e12;
const ROOT: u8 = 1;
const PCA: u8 = 2;
const PCK: u8 = 3;
const AK: u8 = 4;
const FMSPC: [u8; 6] = [0x00, 0x90, 0x6e, 0xa1, 0x00, 0x00];
const OID_SGX_FMSPC: [u8; 12] = [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04];
const OID_SGX_TCB: [u8; 12] = [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02];
const SGX_EXT_OID: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01];
const ECDSA_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const THIS: &[u8] = b"260101000000Z";
const NEXT: &[u8] = b"300101000000Z";

fn signing_key(seed: u8) -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn point(seed: u8) -> Vec<u8> {
    signing_key(seed).verifying_key().to_encoded_point(false).as_bytes().to_vec()
}

fn sign_der(seed: u8, msg: &[u8]) -> Vec<u8> {
    let s: p256::ecdsa::Signature = signing_key(seed).sign(msg);
    s.to_der().as_bytes().to_vec()
}

fn sign_raw(seed: u8, msg: &[u8]) -> Vec<u8> {
    let s: p256::ecdsa::Signature = signing_key(seed).sign(msg);
    s.to_bytes().to_vec()
}

fn alg() -> Vec<u8> {
    w(0x30, &w(0x06, &ECDSA_SHA256))
}

fn cn(n: &[u8]) -> Vec<u8> {
    w(0x30, &w(0x31, &w(0x30, &[w(0x06, &[0x55, 0x04, 0x03]), w(0x0c, n)].concat())))
}

fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let crit = if critical { w(0x01, &[0xff]) } else { vec![] };
    w(0x30, &[w(0x06, oid), crit, w(0x04, value)].concat())
}

fn good_ca() -> Vec<Vec<u8>> {
    vec![ext(&[0x55, 0x1d, 0x13], true, &w(0x30, &w(0x01, &[0xff]))), ext(&[0x55, 0x1d, 0x0f], true, &w(0x03, &[0, 0x04]))]
}

fn not_ca() -> Vec<u8> {
    ext(&[0x55, 0x1d, 0x13], true, &w(0x30, &[]))
}

fn mint_named(seed: u8, issuer_seed: u8, extensions: &[Vec<u8>], issuer: &[u8], subject: &[u8]) -> Vec<u8> {
    let validity = w(0x30, &[w(0x17, b"200101000000Z"), w(0x17, b"400101000000Z")].concat());
    let key_alg = w(0x30, &[w(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]), w(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])].concat());
    let spki = w(0x30, &[key_alg, w(0x03, &[vec![0], point(seed)].concat())].concat());
    let tbs = w(
        0x30,
        &[
            w(0xa0, &w(0x02, &[2])),
            w(0x02, &[seed]),
            alg(),
            issuer.to_vec(),
            validity,
            subject.to_vec(),
            spki,
            w(0xa3, &w(0x30, &extensions.concat())),
        ]
        .concat(),
    );
    let bits = w(0x03, &[vec![0], sign_der(issuer_seed, &tbs)].concat());
    w(0x30, &[tbs, alg(), bits].concat())
}

fn pem(der: &[u8]) -> String {
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", base64::engine::general_purpose::STANDARD.encode(der))
}

fn comp(last: u8, value: &[u8]) -> Vec<u8> {
    w(0x30, &[w(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, last]), w(0x02, value)].concat())
}

/// The FMSPC element followed by the TCB OID and `tcb` (the TLV that must be the TCB SEQUENCE).
fn sgx_blob(tcb: Vec<u8>) -> Vec<u8> {
    [OID_SGX_FMSPC.to_vec(), w(0x04, &FMSPC), OID_SGX_TCB.to_vec(), tcb].concat()
}

struct Chain {
    pem: String,
    pin: String,
}

/// leaf (PCK, with the SGX extension), PCK CA, self-signed root; the pin is the root's SPKI hash.
fn chain() -> Chain {
    let root_name = cn(b"root");
    let pca_name = cn(b"pca");
    let root = mint_named(ROOT, ROOT, &good_ca(), &root_name, &root_name);
    let pca = mint_named(PCA, ROOT, &good_ca(), &root_name, &pca_name);
    let sgx = ext(&SGX_EXT_OID, false, &sgx_blob(w(0x30, &comp(17, &[5]))));
    let leaf = mint_named(PCK, PCA, &[not_ca(), sgx], &pca_name, &cn(b"pck"));
    let pin = Cert::from_der(&root).unwrap().public_key().unwrap().spki_sha256_hex();
    Chain { pem: [pem(&leaf), pem(&pca), pem(&root)].concat(), pin }
}

fn le16(n: u16) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

fn le32(n: usize) -> Vec<u8> {
    (n as u32).to_le_bytes().to_vec()
}

fn header() -> Vec<u8> {
    let mut h = vec![0u8; 48];
    h[0] = 4;
    h[2] = 2;
    h[4] = 0x81;
    h
}

/// A v4 TDX quote around `sig_data`, with nothing after the signature data.
fn quote_of(sig_data: &[u8]) -> Vec<u8> {
    [header(), vec![0u8; 584], le32(sig_data.len()), sig_data.to_vec()].concat()
}

/// A complete quote whose QE report endorses `ak_raw` (the 64-byte attestation key) and whose TD signature is `ak_sig`.
fn genuine_quote(c: &Chain, ak_raw: &[u8], ak_sig: Vec<u8>) -> Vec<u8> {
    let mut qe = vec![0u8; 384];
    qe[0x140..0x140 + 32].copy_from_slice(&Sha256::digest(ak_raw));
    let qe_sig = sign_raw(PCK, &qe);
    let inner = [le16(5), le32(c.pem.len()), c.pem.clone().into_bytes()].concat();
    let outer = [qe, qe_sig, vec![0, 0], inner].concat();
    let sig_data = [ak_sig, ak_raw.to_vec(), le16(6), le32(outer.len()), outer].concat();
    quote_of(&sig_data)
}

// ---------------------------------------------------------------------------------------------------------------------
// dcap.rs: parse_dcap_quote bounds (87, 90, 93, 99)

/// quote signature + attestation key + the outer cert-data header declaring `outer_size`.
fn sig_prefix(outer_size: usize) -> Vec<u8> {
    [vec![0u8; 64], vec![0u8; 64], le16(6), le32(outer_size)].concat()
}

#[test]
fn a_quote_truncated_inside_the_qe_report_is_refused_not_read_past() {
    let q = quote_of(&sig_prefix(0));
    assert_eq!(parse_dcap_quote(&q).err().as_deref(), Some("parseDcapQuote: truncated reading QE report"));
}

#[test]
fn a_quote_truncated_inside_the_qe_report_signature_is_refused() {
    let q = quote_of(&[sig_prefix(384), vec![0u8; 384]].concat());
    assert_eq!(parse_dcap_quote(&q).err().as_deref(), Some("parseDcapQuote: truncated reading QE report signature"));
}

#[test]
fn a_quote_truncated_at_the_qe_auth_data_size_is_refused() {
    let q = quote_of(&[sig_prefix(448), vec![0u8; 448]].concat());
    assert_eq!(parse_dcap_quote(&q).err().as_deref(), Some("parseDcapQuote: truncated reading QE auth-data size"));
}

#[test]
fn a_quote_truncated_at_the_inner_cert_data_header_is_refused() {
    let q = quote_of(&[sig_prefix(450), vec![0u8; 448], vec![0, 0]].concat());
    assert_eq!(parse_dcap_quote(&q).err().as_deref(), Some("parseDcapQuote: truncated reading inner cert-data header"));
}

// ---------------------------------------------------------------------------------------------------------------------
// dcap.rs: extract_pck_fmspc_and_tcb (171, 180, 184)

#[test]
fn the_tcb_extension_must_be_a_sequence() {
    let set_not_sequence = sgx_blob(w(0x31, &comp(17, &[5])));
    assert_eq!(extract_pck_fmspc_and_tcb(&set_not_sequence).err().as_deref(), Some("extractPckFmspcAndTcb: malformed TCB SEQUENCE"));
    // control: the same content under SEQUENCE parses
    assert_eq!(extract_pck_fmspc_and_tcb(&sgx_blob(w(0x30, &comp(17, &[5])))).unwrap().pcesvn, 5);
}

#[test]
fn each_tcb_component_must_be_a_sequence() {
    let oid = w(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 17]);
    let as_set = w(0x31, &[oid, w(0x02, &[5])].concat());
    let r = extract_pck_fmspc_and_tcb(&sgx_blob(w(0x30, &as_set)));
    assert_eq!(r.err().as_deref(), Some("extractPckFmspcAndTcb: malformed TCB component"));
}

#[test]
fn each_tcb_component_must_open_with_an_oid() {
    // the first element is an OCTET STRING whose last content byte is 17: with the tag unchecked it would read as the PCESVN arc
    let not_an_oid = w(0x04, &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 17]);
    let c = w(0x30, &[not_an_oid, w(0x02, &[5])].concat());
    let r = extract_pck_fmspc_and_tcb(&sgx_blob(w(0x30, &c)));
    assert_eq!(r.err().as_deref(), Some("extractPckFmspcAndTcb: TCB component missing OID"));
}

// ---------------------------------------------------------------------------------------------------------------------
// dcap.rs: verify_genuine_tdx_quote attestation key point (364)

#[test]
fn an_attestation_key_off_the_curve_is_refused_by_name() {
    let c = chain();
    // control: a real key with a real TD signature passes every check up to and including the policy
    let ak_raw = point(AK)[1..].to_vec();
    let signed = [header(), vec![0u8; 584]].concat();
    let good = genuine_quote(&c, &ak_raw, sign_raw(AK, &signed));
    assert_eq!(verify_genuine_tdx_quote(&good, &c.pin, NOW, &DcapPolicy::default()).err(), None);

    // the QE report endorses these 64 bytes (so the binding check passes), but they are not a P-256 point
    let bad = genuine_quote(&c, &[1u8; 64], vec![0u8; 64]);
    assert_eq!(verify_genuine_tdx_quote(&bad, &c.pin, NOW, &DcapPolicy::default()).err().as_deref(), Some("attestation public key is not a valid P-256 point"));
}

// ---------------------------------------------------------------------------------------------------------------------
// dcap.rs: verify_intel_pck_chain (241, 242, 259)

#[test]
fn a_clock_that_is_not_finite_is_refused_by_name() {
    let c = chain();
    assert!(verify_intel_pck_chain(&c.pem, &c.pin, NOW).is_ok());
    for now in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(verify_intel_pck_chain(&c.pem, &c.pin, now).err(), Some(("nowMs is not a finite number".to_string(), false)), "{now}");
    }
}

/// A -> B -> A: the walk must stop at the first repeated subject. Without that stop it never ends, so the call runs on a thread
/// with a deadline: a hang is a failure here, not a stuck test run.
#[test]
fn an_issuer_cycle_ends_the_chain_walk_and_is_refused() {
    let (a, b) = (cn(b"a"), cn(b"b"));
    let ca = mint_named(10, 11, &good_ca(), &b, &a);
    let cb = mint_named(11, 10, &good_ca(), &a, &b);
    let text = [pem(&ca), pem(&cb)].concat();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(verify_intel_pck_chain(&text, &"0".repeat(64), NOW).err());
    });
    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(got) => assert_eq!(got, Some(("PCK chain does not terminate in a self-signed root".to_string(), false))),
        Err(_) => panic!("the chain walk did not stop on an issuer cycle"),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// dcap.rs: CRL parsing (497, 516, 537)

fn crl_tbs(tag: u8, issuer: Vec<u8>, rest: &[Vec<u8>]) -> Vec<u8> {
    w(tag, &[w(0x02, &[1]), alg(), issuer, rest.concat()].concat())
}

fn crl_signed(tbs: Vec<u8>, seed: u8) -> Vec<u8> {
    let bits = w(0x03, &[vec![0], sign_der(seed, &tbs)].concat());
    w(0x30, &[tbs, alg(), bits].concat())
}

fn crl_key() -> PubKey {
    PubKey::Ec { curve: EcCurve::P256, point: point(1) }
}

#[test]
fn a_crl_tbs_must_be_a_sequence() {
    let times = [w(0x17, THIS), w(0x17, NEXT)];
    let good = crl_signed(crl_tbs(0x30, cn(b"i"), &times), 1);
    assert_eq!(verify_crl(&good, &crl_key(), NOW), Ok(vec![]));
    let bad = crl_signed(crl_tbs(0x31, cn(b"i"), &times), 1);
    assert_eq!(verify_crl(&bad, &crl_key(), NOW), Err("CRL parse failed: CRL: bad TBSCertList".to_string()));
}

#[test]
fn a_crl_issuer_must_be_a_sequence() {
    let times = [w(0x17, THIS), w(0x17, NEXT)];
    let bad = crl_signed(crl_tbs(0x30, w(0x31, &[]), &times), 1);
    assert_eq!(verify_crl(&bad, &crl_key(), NOW), Err("CRL parse failed: CRL: bad issuer".to_string()));
}

#[test]
fn a_crl_revoked_entry_must_open_with_an_integer_serial() {
    let entry = |serial: Vec<u8>| w(0x30, &w(0x30, &[serial, w(0x17, THIS)].concat()));
    let ok = crl_signed(crl_tbs(0x30, cn(b"i"), &[w(0x17, THIS), w(0x17, NEXT), entry(w(0x02, &[1]))]), 1);
    assert_eq!(verify_crl(&ok, &crl_key(), NOW), Ok(vec!["1".to_string()]));
    let bad = crl_signed(crl_tbs(0x30, cn(b"i"), &[w(0x17, THIS), w(0x17, NEXT), entry(w(0x04, &[1]))]), 1);
    assert_eq!(verify_crl(&bad, &crl_key(), NOW), Err("CRL parse failed: CRL: bad revoked entry".to_string()));
}

// ---------------------------------------------------------------------------------------------------------------------
// operations.rs: Executor::recheck_now (721, 722, 725, 726, 730)

struct Fx {
    grant: Value,
    pcactn: Value,
    op: Operation,
    now: i64,
    audience: String,
}

fn fx() -> Fx {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/authorize-fixtures.json")).unwrap();
    let d = strict_parse(&text).unwrap();
    let s = &d["cases"][0]["steps"][0];
    Fx {
        grant: d["cases"][0]["grant"].clone(),
        pcactn: s["pcactn"].clone(),
        op: Operation::from_json(&s["operation"]).unwrap(),
        now: d["now"].as_i64().unwrap(),
        audience: d["audience"].as_str().unwrap().to_string(),
    }
}

fn executor(f: &Fx, az: AuthorizeOptions, store: Arc<dyn OperationStore>) -> Executor {
    let (grant, now) = (f.grant.clone(), f.now);
    Executor::new(az, f.audience.clone(), move |_: &str| Ok(Some(grant.clone())), store).with_clock(move || now)
}

/// An operation store that runs `on_create` the moment the executor records the operation: after `authorize` allowed it and
/// before the executor's own re-check, which is the window a late revocation lands in.
struct Hooked {
    inner: MemoryOperationStore,
    on_create: Box<dyn Fn() + Send + Sync>,
}

impl OperationStore for Hooked {
    fn create(&self, record: OperationRecord) -> Result<CreateOutcome, StoreError> {
        (self.on_create)();
        self.inner.create(record)
    }
    fn get(&self, id: &str) -> Result<Option<OperationRecord>, StoreError> {
        self.inner.get(id)
    }
    fn transition(&self, id: &str, from: OperationState, next: OperationRecord) -> Result<bool, StoreError> {
        self.inner.transition(id, from, next)
    }
    fn list_open(&self) -> Result<Option<Vec<OperationRecord>>, StoreError> {
        self.inner.list_open()
    }
}

fn aborted_reason(out: &ExecutorOutcome) -> String {
    match out {
        ExecutorOutcome::Executed(ExecuteOutcome::Aborted { reason, .. }) => reason.clone(),
        other => panic!("expected an aborted execution: {other:?}"),
    }
}

/// `hook` is what the revocation hook answers once the operation is recorded (before that it answers "not revoked").
fn run_with_late_revocation(hook: fn() -> Result<bool, String>) -> (bool, String) {
    let f = fx();
    let created = Arc::new(AtomicBool::new(false));
    let on_create = created.clone();
    let store = Arc::new(Hooked { inner: MemoryOperationStore::new(), on_create: Box::new(move || on_create.store(true, Ordering::SeqCst)) });
    let az = AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), move |_: &Value, _: &Value| if created.load(Ordering::SeqCst) { hook() } else { Ok(false) }).with_plan(Some(atlas_pca::SINGLE_STEP)).with_risk(atlas_pca::insecure_calm_risk)
        .with_plans(Arc::new(PlanRegistry::new()))
        .with_provenance_mediators(common::harness_pins())
        .with_provenance_bundle(common::principal_direct);
    let ran = std::cell::Cell::new(false);
    let out = executor(&f, az, store).execute(&f.pcactn, &f.op, |_| {
        ran.set(true);
        Ok(json!(1))
    });
    (ran.get(), aborted_reason(&out))
}

#[test]
fn a_grant_revoked_after_authorization_aborts_the_execution() {
    let (ran, reason) = run_with_late_revocation(|| Ok(true));
    assert!(!ran);
    assert_eq!(reason, "recheck: the grant has been revoked");
}

#[test]
fn a_revocation_check_that_fails_at_recheck_time_aborts_the_execution() {
    let (ran, reason) = run_with_late_revocation(|| Err("store down".to_string()));
    assert!(!ran);
    assert_eq!(reason, "recheck: revocation could not be checked");
}

#[test]
fn a_plan_revoked_after_authorization_aborts_the_execution() {
    let f = fx();
    let p = &f.pcactn;
    let (root, grant_ref) = (p["plan"]["root"].as_str().unwrap().to_string(), p["grant_ref"].as_str().unwrap().to_string());
    let n = json!({"id": p["plan"]["node_id"], "verb": f.op.verb, "resource": f.op.resource, "params_digest": p["action"]["params_digest"], "reversibility_class": p["action"]["reversibility_class"]});
    let reg = Arc::new(PlanRegistry::new());
    assert!(reg.draft(&grant_ref, std::slice::from_ref(&n)).is_ok());
    assert!(reg.validate(&grant_ref, &root).is_ok() && reg.commit(&grant_ref, &root).is_ok());
    assert!(reg.authorize(&grant_ref, &root, Some(&PlanApproval { by: "p".into(), expires_at: None })).is_ok());

    let (r2, g2, root2) = (reg.clone(), grant_ref.clone(), root.clone());
    let store = Arc::new(Hooked {
        inner: MemoryOperationStore::new(),
        on_create: Box::new(move || {
            assert!(r2.revoke(&g2, &root2, "late").is_ok());
        }),
    });
    let az = AuthorizeOptions::new(Arc::new(MemoryStateStore::new()), |_: &Value, _: &Value| Ok(false)).with_plan(Some(atlas_pca::SINGLE_STEP)).with_risk(atlas_pca::insecure_calm_risk)
        .with_plans(reg)
        .with_provenance_mediators(common::harness_pins())
        .with_provenance_bundle(common::principal_direct);
    let ran = std::cell::Cell::new(false);
    let out = executor(&f, az, store).execute(&f.pcactn, &f.op, |_| {
        ran.set(true);
        Ok(json!(1))
    });
    assert!(!ran.get());
    assert_eq!(aborted_reason(&out), format!("recheck: plan {root} is revoked (late)"));
}

// ---------------------------------------------------------------------------------------------------------------------
// operations.rs: KvOperationStore::create on a corrupt stored record (255, 256)

#[test]
fn creating_over_a_corrupt_record_is_an_error_not_a_fresh_create() {
    let kv = Arc::new(MemoryAtomicKv::new());
    kv.update("pca-op:bad", &mut |_| Some(json!({"state": "nonsense"}))).unwrap();
    let store = KvOperationStore::new(kv);
    let rec = OperationRecord {
        id: "bad".into(),
        state: OperationState::Pending,
        verb: "v".into(),
        resource: "/r".into(),
        params_digest: params_digest(None),
        reversibility: Reversibility::Reversible,
        started_at: 10,
        executing_at: None,
        finished_at: None,
        result: None,
        error: None,
    };
    assert_eq!(store.create(rec), Err(StoreError("the stored record of operation bad is malformed".into())));
}

// ---------------------------------------------------------------------------------------------------------------------
// sqlite_store.rs: the once-table prune must report its failure (97)

#[cfg(feature = "sqlite")]
#[test]
fn a_failing_prune_fails_consume_once() {
    let d = std::env::temp_dir().join(format!("pca-k05b-g3-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let path = d.join("once.db");
    let store = SqliteStateStore::open(&path).unwrap();
    assert!(store.consume_once("a", 100, 50).unwrap());
    // from here on, deleting an elapsed row aborts
    let other = rusqlite::Connection::open(&path).unwrap();
    other
        .execute_batch("CREATE TRIGGER no_prune BEFORE DELETE ON pca_replay_once BEGIN SELECT RAISE(ABORT, 'prune refused'); END;")
        .unwrap();
    drop(other);
    // "a" (retain_until 100) has elapsed at now = 200, so the prune hits it
    let r = store.consume_once("b", 300, 200);
    assert!(r.is_err(), "{r:?}");
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------------------------------------------------
// intent_v2.rs: model rules (910, 930)

const MAX_SAFE: i64 = 9_007_199_254_740_991;

fn grant_with_envelope(extra: Value) -> Value {
    let mut env = json!({
        "type": "envelope", "agent_binding": {}, "caveats": [], "goal_commit": "g", "predicates": [],
        "risk_policy": {"bMax": 1000, "kappa": 1, "lambda": 0, "rho": 0, "theta1": 0.5, "theta2": 0.8,
                        "weights": {"alpha": 0, "beta": 0, "delta": 0, "epsilon": 0, "gamma": 0, "zeta": 0}},
    });
    if let Some(o) = extra.as_object() {
        for (k, v) in o {
            env[k.as_str()] = v.clone();
        }
    }
    json!({"caveats": [env]})
}

fn bare_pcactn() -> Value {
    json!({"action": {"verb": "v.read", "resource": "/r"}})
}

#[test]
fn the_model_rules_fail_closed_on_a_clock_that_is_not_a_safe_integer() {
    let grant = grant_with_envelope(json!({"tighten": []}));
    let tighten = |ok: bool, reason: &str| vec![IntentV2Check { name: "tighten", ok, reason: reason.to_string() }];
    assert_eq!(decide_intent_v2(&bare_pcactn(), &grant, None, 1000).checks, tighten(true, ""));
    assert_eq!(
        decide_intent_v2(&bare_pcactn(), &grant, None, MAX_SAFE + 1).checks,
        tighten(false, "the verifier clock is not a safe integer (fail closed)")
    );
    assert_eq!(
        decide_intent_v2(&bare_pcactn(), &grant, None, -MAX_SAFE - 1).checks,
        tighten(false, "the verifier clock is not a safe integer (fail closed)")
    );
}

#[test]
fn a_layer_ceiling_that_reads_a_model_derived_path_is_refused_by_rule_21() {
    let grant = grant_with_envelope(json!({}));
    let ctx = IntentV2Context::from_json(&json!({
        "layers": {"org": {"predicates": [{"verb": "v.read", "where": [{"field": "env.class.risk", "op": "eq", "value": 1}]}]}}
    }))
    .unwrap();
    let d = decide_intent_v2(&bare_pcactn(), &grant, Some(&ctx), 1000);
    assert_eq!(
        d.checks,
        vec![IntentV2Check {
            name: "tighten",
            ok: false,
            reason: "a grant's where reads model-derived path(s) env.class.risk: a model may only tighten (move them into tighten[]) (rule 21)".to_string(),
        }]
    );
    // control: without the layers member nothing model-derived is read, so no tighten check is reported
    let none = IntentV2Context::from_json(&json!({})).unwrap();
    assert_eq!(decide_intent_v2(&bare_pcactn(), &grant, Some(&none), 1000).checks, vec![]);
}

// ---------------------------------------------------------------------------------------------------------------------
// decision.rs: fold_v2_reasons (590, 591)

#[test]
fn only_failing_checks_add_a_reason_line() {
    let c = |name: &str, ok: bool, reason: Option<&str>| V2CheckResult { name: name.into(), ok, reason: reason.map(String::from) };
    let v2 = [c("a", true, Some("x")), c("b", false, Some("y")), c("c", false, None), c("b", false, Some("y"))];
    assert_eq!(fold_v2_reasons(&["base".to_string()], &v2), vec!["base".to_string(), "b: y".to_string()]);
}

// ---------------------------------------------------------------------------------------------------------------------
// approval.rs: the render flattening (191)

#[test]
fn a_nested_object_under_an_empty_top_level_key_flattens_without_a_leading_dot() {
    let def = json!({"v":1,"kind":"pca-action-def","verb":"bank.transfer.eur","title":"Send a transfer","description":"Sends money to a payee.","effects":["pay"],"resource":{"type":"bank.account","id":"*","scope":"one"},"params":{"amount":{"type":"integer","min":1,"max":1000000,"role":"money.amount","unit":{"kind":"money","ccy":"EUR","exp":2}},"to.iban":{"type":"string","role":"party.payee","format":"iban"},"to.name":{"type":"string","max_len":64,"required":false}},"reversibility":"irreversible","idempotency":{"mode":"natural"},"review":{"state":"authored"}});
    let inner = json!({"amount": 100, "to": {"iban": "DE89370400440532013000", "name": "Acme"}});
    let control = render_approval(&def, &inner, false).unwrap();
    let ids: Vec<&str> = control["fields"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["amount", "to.iban", "to.name"]);
    // the empty key adds no path segment: the paths are the same as without it
    let under_empty = render_approval(&def, &json!({ "": inner }), false).unwrap();
    assert_eq!(under_empty, control);
}
