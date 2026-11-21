//! Fail-closed table of the vendor attestation verifiers: every row is "missing / invalid X => exact result". A row passes only
//! when the WHOLE answer equals the expectation, so a regression that turns a denial into a pass (or into a different denial)
//! fails here. The inputs are tiny and need no genuine evidence: each denial happens before any signature is checked.

use atlas_pca::attest::{run_attestation_vector, verifier_from_config, Binding};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000;

fn binding() -> Binding {
    Binding { holder_pub: "holder".into(), grant_ref: "grant".into(), epoch: 1.0, nonce: "nonce".into() }
}

fn run(vendor: &str, config: Value, evidence: Option<Value>) -> Value {
    run_attestation_vector(vendor, &config, evidence.as_ref(), NOW, Some(&binding()))
}

fn denial(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

fn refusal(msg: &str) -> Value {
    json!({ "construct_error": msg })
}

fn b64(b: &[u8]) -> String {
    atlas_pca::attest::util::b64_std(b)
}

fn snp_cfg() -> Value {
    json!({ "family": "genoa", "binding": "report-data", "policy": { "measurements": [ "00".repeat(48) ] } })
}
fn dcap_cfg() -> Value {
    json!({ "binding": "report-data", "policy": { "mrtds": [ "00".repeat(48) ] } })
}
fn maa_cfg() -> Value {
    json!({ "trustedIssuers": ["https://issuer.example"], "trustAnchors": { "rootSpkiSha256": ["00"] }, "policy": { "tdxMrtds": ["00"] } })
}
fn gcp_cfg() -> Value {
    json!({ "trustedIssuers": ["https://confidentialcomputing.googleapis.com"], "trustAnchors": { "trustedKeySpki": ["00"] }, "policy": { "imageDigests": ["sha256:00"] } })
}
fn nv_cfg() -> Value {
    json!({ "rootSpkiSha256": ["00"], "policy": { "measurements": { "0": "00" } } })
}

fn with(mut base: Value, path: &[&str], v: Value) -> Value {
    let mut cur = &mut base;
    for k in &path[..path.len() - 1] {
        cur = cur.as_object_mut().unwrap().entry(k.to_string()).or_insert_with(|| json!({}));
    }
    cur.as_object_mut().unwrap().insert(path[path.len() - 1].to_string(), v);
    base
}

fn check(rows: Vec<(&str, Value, Value)>) {
    let bad: Vec<String> = rows.into_iter().filter(|(_, got, want)| got != want).map(|(n, got, want)| format!("{n}: got {got} want {want}")).collect();
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn amd_sev_snp_fails_closed() {
    let ev = |report: Vec<u8>, vcek: &str| json!({ "report": b64(&report), "vcekDer": b64(vcek.as_bytes()), "askArkPem": "" });
    let mut sig_block = vec![0u8; 1184];
    sig_block[0x330] = 1;
    let rows = vec![
        ("family missing", run("amd-sev-snp", with(snp_cfg(), &["family"], Value::Null), None), refusal("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'")),
        ("family unknown", run("amd-sev-snp", with(snp_cfg(), &["family"], json!("zen9")), None), refusal("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'")),
        ("binding unknown", run("amd-sev-snp", with(snp_cfg(), &["binding"], json!("nope")), None), refusal("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'")),
        ("measurements empty", run("amd-sev-snp", with(snp_cfg(), &["policy", "measurements"], json!([])), None), refusal("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")),
        ("policy missing", run("amd-sev-snp", with(snp_cfg(), &["policy"], Value::Null), None), refusal("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")),
        ("no evidence", run("amd-sev-snp", snp_cfg(), None), denial("no AMD SEV-SNP evidence for this action")),
        ("evidence without the VCEK", run("amd-sev-snp", snp_cfg(), Some(json!({ "report": b64(&[0u8; 1184]) }))), denial("no AMD SEV-SNP evidence for this action")),
        ("report shorter than the parse minimum", run("amd-sev-snp", snp_cfg(), Some(ev(vec![0; 100], "x"))), denial("SEV-SNP report invalid: report parse failed: parseSevSnpReport: report too short (100 < 816)")),
        ("report of a non-canonical length", run("amd-sev-snp", snp_cfg(), Some(ev(vec![0; 900], "x"))), denial("SEV-SNP report invalid: report length 900 is not the canonical 1184")),
        ("report with a non-zero reserved signature byte", run("amd-sev-snp", snp_cfg(), Some(ev(sig_block, "x"))), denial("SEV-SNP report invalid: report signature block has non-zero reserved bytes")),
    ];
    check(rows);
    // a canonical report with an unusable VCEK is refused by the certificate parser, never accepted
    let r = run("amd-sev-snp", snp_cfg(), Some(ev(vec![0; 1184], "not a certificate")));
    assert_eq!(r["ok"], json!(false));
    assert!(r["reason"].as_str().unwrap().starts_with("SEV-SNP report invalid: cert chain invalid: AMD chain verification error: "), "{r}");
}

#[test]
fn intel_tdx_dcap_fails_closed() {
    let quote = |len: usize, version: u8| {
        let mut q = vec![0u8; len];
        q[0] = version;
        b64(&q)
    };
    let rows = vec![
        ("binding unknown", run("intel-tdx-dcap", with(dcap_cfg(), &["binding"], json!("x")), None), refusal("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'")),
        ("mrtds missing", run("intel-tdx-dcap", with(dcap_cfg(), &["policy", "mrtds"], Value::Null), None), refusal("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")),
        ("mrtds empty", run("intel-tdx-dcap", with(dcap_cfg(), &["policy", "mrtds"], json!([])), None), refusal("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")),
        ("mrtd of the wrong length", run("intel-tdx-dcap", with(dcap_cfg(), &["policy", "mrtds"], json!(["abcd"])), None), refusal("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)")),
        ("mrSeams empty", run("intel-tdx-dcap", with(dcap_cfg(), &["policy", "mrSeams"], json!([])), None), refusal("createIntelDcapVerifier: policy.mrSeams, if given, must be a NON-EMPTY list")),
        ("mrSignerSeams entry of the wrong length", run("intel-tdx-dcap", with(dcap_cfg(), &["policy", "mrSignerSeams"], json!(["00"])), None), refusal("createIntelDcapVerifier: every mrSignerSeams entry must be 96 hex chars (48 bytes)")),
        ("no evidence", run("intel-tdx-dcap", dcap_cfg(), None), denial("no Intel DCAP quote for this action")),
        ("evidence without a quote", run("intel-tdx-dcap", dcap_cfg(), Some(json!({}))), denial("no Intel DCAP quote for this action")),
        ("quote too short", run("intel-tdx-dcap", dcap_cfg(), Some(json!({ "quote": quote(10, 4) }))), denial("DCAP quote invalid: quote parse failed: parseDcapQuote: too short for header + TD report + sig length")),
        ("quote of another version", run("intel-tdx-dcap", dcap_cfg(), Some(json!({ "quote": quote(700, 3) }))), denial("DCAP quote invalid: quote parse failed: parseDcapQuote: unsupported quote version 3 (expected 4)")),
    ];
    check(rows);
}

#[test]
fn azure_maa_fails_closed() {
    let rows = vec![
        ("no issuers", run("azure-maa", with(maa_cfg(), &["trustedIssuers"], json!([])), None), refusal("createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")),
        ("empty issuer", run("azure-maa", with(maa_cfg(), &["trustedIssuers"], json!([""])), None), refusal("createAzureMaaVerifier: every trusted issuer must be a non-empty URL string")),
        ("no trust anchors", run("azure-maa", with(maa_cfg(), &["trustAnchors"], json!({})), None), refusal("createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) \u{2014} accept-all is not permitted")),
        ("no measurement allowlist", run("azure-maa", with(maa_cfg(), &["policy"], json!({})), None), refusal("createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)")),
        ("unknown minimum-TCB field", run("azure-maa", with(maa_cfg(), &["policy", "sevSnpMinTcb"], json!({ "nope": 1 })), None), refusal("createAzureMaaVerifier: policy.sevSnpMinTcb.nope is not a known field (bootloader | snp | microcode | tee)")),
        ("negative minimum TCB", run("azure-maa", with(maa_cfg(), &["policy", "sevSnpMinTcb"], json!({ "snp": -1 })), None), refusal("createAzureMaaVerifier: policy.sevSnpMinTcb.snp must be a non-negative integer")),
        ("no token", run("azure-maa", maa_cfg(), None), denial("no Azure MAA token for this action")),
        ("empty token", run("azure-maa", maa_cfg(), Some(json!({ "token": "" }))), denial("no Azure MAA token for this action")),
        ("two segments", run("azure-maa", maa_cfg(), Some(json!({ "token": "a.b" }))), denial("MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts")),
        ("empty signature segment", run("azure-maa", maa_cfg(), Some(json!({ "token": "YQ.YQ." }))), denial("MAA token parse failed: parseMaaJwt: empty JWS segment")),
        ("padded segment", run("azure-maa", maa_cfg(), Some(json!({ "token": "YQ==.YQ.YQ" }))), denial("MAA token parse failed: parseMaaJwt: malformed JSON segment: non-canonical compact JWS: bad-character")),
        ("segment of impossible length", run("azure-maa", maa_cfg(), Some(json!({ "token": "YQYQY.YQ.YQ" }))), denial("MAA token parse failed: parseMaaJwt: malformed JSON segment: non-canonical compact JWS: non-canonical-base64url (impossible length)")),
    ];
    check(rows);
}

#[test]
fn gcp_confidential_space_fails_closed() {
    let rows = vec![
        ("no issuers", run("gcp-confidential-space", with(gcp_cfg(), &["trustedIssuers"], json!([])), None), refusal("createGcpConfidentialSpaceVerifier: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs")),
        ("empty issuer", run("gcp-confidential-space", with(gcp_cfg(), &["trustedIssuers"], json!([""])), None), refusal("createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string")),
        ("no anchors", run("gcp-confidential-space", with(gcp_cfg(), &["trustAnchors"], json!({})), None), refusal("createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) \u{2014} accept-all is not permitted")),
        ("no image digests", run("gcp-confidential-space", with(gcp_cfg(), &["policy", "imageDigests"], json!([])), None), refusal("createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")),
        ("empty tee type list", run("gcp-confidential-space", with(gcp_cfg(), &["policy", "allowedTeeTypes"], json!([])), None), refusal("createGcpConfidentialSpaceVerifier: policy.allowedTeeTypes, when present, must be non-empty")),
        ("no token", run("gcp-confidential-space", gcp_cfg(), None), denial("no GCP Confidential Space token for this action")),
        ("two segments", run("gcp-confidential-space", gcp_cfg(), Some(json!({ "token": "a.b" }))), denial("Confidential Space token parse failed: parseGcpCsJwt: a compact JWS has exactly three dot-separated parts")),
        ("empty header segment", run("gcp-confidential-space", gcp_cfg(), Some(json!({ "token": ".YQ.YQ" }))), denial("Confidential Space token parse failed: parseGcpCsJwt: empty JWS segment")),
    ];
    check(rows);
}

#[test]
fn nvidia_gpu_spdm_fails_closed() {
    let rows = vec![
        ("no root pin", run("nvidia-gpu-spdm", with(nv_cfg(), &["rootSpkiSha256"], json!([])), None), refusal("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")),
        ("no measurements and no collateral", run("nvidia-gpu-spdm", with(nv_cfg(), &["policy", "measurements"], json!({})), None), refusal("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)")),
        ("measurement index out of range", run("nvidia-gpu-spdm", with(nv_cfg(), &["policy", "measurements"], json!({ "300": "00" })), None), refusal("createNvidiaSpdmVerifier: measurement index out of range")),
        ("collateral without a pinned RIM root", run("nvidia-gpu-spdm", with(nv_cfg(), &["collateral"], json!({ "rimRootSpkiSha256": [] })), None), refusal("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root")),
        ("malformed firmware floor", run("nvidia-gpu-spdm", with(nv_cfg(), &["collateral"], json!({ "rimRootSpkiSha256": ["00"], "firmware": { "minDriverVersion": "x" } })), None), refusal("nvidiaCollateralHook: malformed minDriverVersion 'x'")),
        ("no evidence", run("nvidia-gpu-spdm", nv_cfg(), None), denial("no NVIDIA GPU evidence for this action")),
        ("evidence without a chain", run("nvidia-gpu-spdm", nv_cfg(), Some(json!({ "evidence": b64(&[0u8; 200]) }))), denial("no NVIDIA GPU evidence for this action")),
        ("chain without a certificate", run("nvidia-gpu-spdm", nv_cfg(), Some(json!({ "evidence": b64(&[0u8; 200]), "certChainPem": "" }))), denial("device chain unparseable: parsePemChain: no certificates found")),
    ];
    check(rows);
}

#[test]
fn an_unknown_vendor_or_a_non_object_configuration_is_refused() {
    assert!(verifier_from_config("amd-sev", &json!({})).is_err());
    assert!(verifier_from_config("amd-sev-snp", &json!(null)).is_err());
    assert!(verifier_from_config("amd-sev-snp", &json!([])).is_err());
}

#[test]
fn a_missing_expected_binding_is_a_denial() {
    let r = run_attestation_vector("nvidia-gpu-spdm", &nv_cfg(), None, NOW, None);
    assert_eq!(r, denial("no expected attestation binding supplied"));
}

#[test]
fn identity_overrides_never_turn_a_denial_into_a_pass() {
    let cfg = with(nv_cfg(), &["identity_overrides"], json!({ "model_id": "m" }));
    assert_eq!(run("nvidia-gpu-spdm", cfg, None), denial("no NVIDIA GPU evidence for this action"));
}
