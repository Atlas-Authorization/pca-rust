//! A malformed allowlist never means no list: the verifier refuses to exist rather than drop the gate.
use atlas_pca::attest::verifier_from_config;
use atlas_pca::serde_json::{json, Value};

const M48: &str = "aa7c9da55c1386e5b1653b125978beda7b3f95a85aeb0f9ddbbdb783ce056a28c9d021da239c34a58c3a657654270eef";
const H32: &str = "fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e";

fn refused(vendor: &str, base: &Value, section: &str, key: &str, want: &str) {
    let mut good = base.clone();
    good[section][key] = json!(["aa"]);
    assert_eq!(verifier_from_config(vendor, &good).err(), None, "{vendor} {key}: strings are fine");
    let mut mixed = base.clone();
    mixed[section][key] = json!(["aa", 1]);
    assert_eq!(verifier_from_config(vendor, &mixed).err().as_deref(), Some(want), "{vendor} {key}");
}

#[test]
fn amd_lists() {
    let cfg = json!({"family": "genoa", "binding": "report-data", "policy": {"measurements": [M48]}});
    let want = |k: &str| format!("createAmdSnpVerifier: policy.{k} must list only strings");
    refused("amd-sev-snp", &cfg, "policy", "hostData", &want("hostData"));
    refused("amd-sev-snp", &cfg, "policy", "chipIds", &want("chipIds"));
    refused("amd-sev-snp", &cfg, "policy", "measurements", &want("measurements"));
}

#[test]
fn intel_lists_and_collateral() {
    let cfg = json!({"binding": "report-data", "policy": {"mrtds": [M48]}});
    let want = |k: &str| format!("createIntelDcapVerifier: policy.{k} must list only strings");
    refused("intel-tdx-dcap", &cfg, "policy", "fmspcs", &want("fmspcs"));
    refused("intel-tdx-dcap", &cfg, "policy", "rtmrs", &want("rtmrs"));
    let mut bad = cfg.clone();
    bad["policy"]["collateral"] = json!({"acceptStatuses": "UpToDate"});
    assert_eq!(verifier_from_config("intel-tdx-dcap", &bad).err().as_deref(), Some("createIntelDcapVerifier: policy.acceptStatuses must be a list"));
    bad["policy"]["collateral"] = json!({"minTcbEvaluationDataNumber": "abc"});
    assert!(verifier_from_config("intel-tdx-dcap", &bad).is_err());
    bad["policy"]["collateral"] = json!({"minTcbEvaluationDataNumber": "5", "acceptStatuses": ["UpToDate", 1]});
    assert_eq!(verifier_from_config("intel-tdx-dcap", &bad).err(), None);
}

#[test]
fn maa_lists() {
    let cfg = json!({"trustedIssuers": ["https://i"], "trustAnchors": {"rootSpkiSha256": [H32]}, "policy": {"tdxMrtds": [M48]}});
    let want = |k: &str| format!("createAzureMaaVerifier: policy.{k} must list only strings");
    refused("azure-maa", &cfg, "policy", "sevSnpHostData", &want("sevSnpHostData"));
    refused("azure-maa", &cfg, "policy", "tdxRtmrs", &want("tdxRtmrs"));
    refused("azure-maa", &cfg, "policy", "sevSnpMeasurements", &want("sevSnpMeasurements"));
    let mut bad = cfg.clone();
    bad["policy"]["tdxAllowedTcbStatuses"] = json!("UpToDate");
    assert_eq!(verifier_from_config("azure-maa", &bad).err().as_deref(), Some("createAzureMaaVerifier: policy.tdxAllowedTcbStatuses must be a list"));
}

#[test]
fn nvidia_collateral_lists() {
    let cfg = json!({"rootSpkiSha256": [H32], "policy": {"measurements": {}, "leafSubjectIncludes": "GH100"}, "collateral": {"rimRootSpkiSha256": [H32]}});
    refused("nvidia-gpu-spdm", &cfg, "collateral", "requireCrlIssuers", "nvidiaCollateralHook: malformed requireCrlIssuers entry");
    let mut bad = cfg.clone();
    bad["collateral"]["firmware"] = json!({"denyDriverVersions": ["535.1", 1]});
    assert_eq!(verifier_from_config("nvidia-gpu-spdm", &bad).err().as_deref(), Some("nvidiaCollateralHook: malformed denyDriverVersions entry"));
    bad["collateral"]["firmware"] = json!({"denyVbiosVersions": "96.00"});
    assert_eq!(verifier_from_config("nvidia-gpu-spdm", &bad).err().as_deref(), Some("nvidiaCollateralHook: malformed denyVbiosVersions entry"));
}
