//! `verifier_from_config(vendor, config)`: the one way to build a vendor verifier from its serialisable configuration
//! (the same keys in every language), plus the replay helpers of the conformance vectors.

use super::dcap::DcapVerifier;
use super::der::{check_chain_roles, der_validity_ms, ext_value_hex, parse_cert_extensions, parse_der_time, parse_tbs_extensions, read_cert_role_info, tbs_of_certificate, unrecognised_critical_extension};
use super::gcp::GcpVerifier;
use super::maa::MaaVerifier;
use super::nvidia::NvidiaVerifier;
use super::snp::SnpVerifier;
use super::util::{b64_lenient, b64_std};
use super::{AttResult, Binding};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    AmdSevSnp,
    IntelTdxDcap,
    AzureMaa,
    GcpConfidentialSpace,
    NvidiaGpuSpdm,
}

impl Vendor {
    pub fn from_name(s: &str) -> Option<Vendor> {
        match s {
            "amd-sev-snp" => Some(Vendor::AmdSevSnp),
            "intel-tdx-dcap" => Some(Vendor::IntelTdxDcap),
            "azure-maa" => Some(Vendor::AzureMaa),
            "gcp-confidential-space" => Some(Vendor::GcpConfidentialSpace),
            "nvidia-gpu-spdm" => Some(Vendor::NvidiaGpuSpdm),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Vendor::AmdSevSnp => "amd-sev-snp",
            Vendor::IntelTdxDcap => "intel-tdx-dcap",
            Vendor::AzureMaa => "azure-maa",
            Vendor::GcpConfidentialSpace => "gcp-confidential-space",
            Vendor::NvidiaGpuSpdm => "nvidia-gpu-spdm",
        }
    }
}

enum Inner {
    Snp(SnpVerifier),
    Dcap(DcapVerifier),
    Maa(MaaVerifier),
    Gcp(GcpVerifier),
    Nvidia(NvidiaVerifier),
}

/// A vendor attestation verifier built from a configuration. It answers whether evidence is genuine, bound to the
/// expected (holder, grant, epoch, nonce) and acceptable to the configured policy.
pub struct HardwareVerifier {
    vendor: Vendor,
    inner: Inner,
    overrides: Option<Map<String, Value>>,
    evidence: Option<Value>,
}

impl HardwareVerifier {
    /// Build the verifier of `vendor` from its configuration object. `Err` is the constructor's refusal (an unusable or
    /// unsafe configuration, for example an empty measurement allowlist).
    pub fn from_config(vendor: Vendor, config: &Value) -> Result<HardwareVerifier, String> {
        let cfg = config.as_object().ok_or_else(|| "verifier configuration must be a JSON object".to_string())?;
        let inner = match vendor {
            Vendor::AmdSevSnp => Inner::Snp(SnpVerifier::from_config(cfg)?),
            Vendor::IntelTdxDcap => Inner::Dcap(DcapVerifier::from_config(cfg)?),
            Vendor::AzureMaa => Inner::Maa(MaaVerifier::from_config(cfg)?),
            Vendor::GcpConfidentialSpace => Inner::Gcp(GcpVerifier::from_config(cfg)?),
            Vendor::NvidiaGpuSpdm => Inner::Nvidia(NvidiaVerifier::from_config(cfg)?),
        };
        let overrides = cfg.get("identity_overrides").and_then(Value::as_object).cloned();
        Ok(HardwareVerifier { vendor, inner, overrides, evidence: None })
    }

    /// The evidence this verifier's resolver answers for every action (a passport carries only a nonce; the evidence
    /// itself reaches the verifier out of band).
    pub fn with_evidence(mut self, evidence: Value) -> HardwareVerifier {
        self.evidence = if evidence.is_null() { None } else { Some(evidence) };
        self
    }

    pub fn vendor(&self) -> Vendor {
        self.vendor
    }

    /// Verify `evidence` (`None`: no evidence for this action) against the expected binding at `now_ms`.
    pub fn verify_evidence(&self, evidence: Option<&Value>, now_ms: i64, expected: &Binding) -> AttResult {
        let e = Some(expected);
        let mut r = match &self.inner {
            Inner::Snp(v) => v.verify(evidence, now_ms, e),
            Inner::Dcap(v) => v.verify(evidence, now_ms, e),
            Inner::Maa(v) => v.verify(evidence, now_ms, e),
            Inner::Gcp(v) => v.verify(evidence, now_ms, e),
            Inner::Nvidia(v) => v.verify(evidence, now_ms, e),
        };
        if let (true, Some(ov), Some(m)) = (r.ok, &self.overrides, r.measured.as_mut()) {
            for (k, v) in ov {
                m.insert(k.clone(), v.clone());
            }
        }
        r
    }

    /// Verify with the evidence given to [`HardwareVerifier::with_evidence`].
    pub fn verify(&self, now_ms: i64, expected: &Binding) -> AttResult {
        self.verify_evidence(self.evidence.as_ref(), now_ms, expected)
    }
}

/// `verifier_from_config(vendor, config)` by vendor name (`amd-sev-snp`, `intel-tdx-dcap`, `azure-maa`,
/// `gcp-confidential-space`, `nvidia-gpu-spdm`).
pub fn verifier_from_config(vendor: &str, config: &Value) -> Result<HardwareVerifier, String> {
    let v = Vendor::from_name(vendor).ok_or_else(|| format!("unknown attestation vendor '{vendor}'"))?;
    HardwareVerifier::from_config(v, config)
}

/// Replay one attestation-evidence vector row: the whole result as JSON, or `{"construct_error": ...}`.
pub fn run_attestation_vector(vendor: &str, config: &Value, evidence: Option<&Value>, now_ms: i64, expected: Option<&Binding>) -> Value {
    let v = match verifier_from_config(vendor, config) {
        Ok(v) => v,
        Err(e) => return json!({ "construct_error": e }),
    };
    match expected {
        Some(b) => v.verify_evidence(evidence, now_ms, b).to_value(),
        None => AttResult::fail("no expected attestation binding supplied").to_value(),
    }
}

// ───────────────────────────── strict X.509 reader rows

fn bytes_of(input: &Value, key: &str) -> Vec<u8> {
    input.get(key).and_then(Value::as_str).map(b64_lenient).unwrap_or_default()
}

fn ext_rows(exts: &[super::der::CertExtension]) -> Value {
    Value::Array(exts.iter().map(|e| json!({ "oid": e.oid, "critical": e.critical, "value": ext_value_hex(e) })).collect())
}

/// Replay one x509 unit row: `{ok: true, value}` or `{ok: false, error}` (the exact message of the TypeScript reader).
pub fn run_x509_vector(func: &str, input: &Value) -> Value {
    let r: Result<Value, String> = (|| -> Result<Value, String> {
        match func {
            "read_cert_role_info" => {
                let i = read_cert_role_info(&bytes_of(input, "cert"))?;
                let mut m = Map::new();
                m.insert("hasBasicConstraints".into(), json!(i.has_basic_constraints));
                m.insert("ca".into(), json!(i.ca));
                if let Some(p) = i.path_len {
                    m.insert("pathLen".into(), json!(p));
                }
                m.insert("hasKeyUsage".into(), json!(i.has_key_usage));
                m.insert("keyCertSign".into(), json!(i.key_cert_sign));
                Ok(Value::Object(m))
            }
            "parse_cert_extensions" => Ok(ext_rows(&parse_cert_extensions(&bytes_of(input, "cert"))?)),
            "parse_tbs_extensions" => Ok(ext_rows(&parse_tbs_extensions(&bytes_of(input, "tbs"))?)),
            "tbs_of_certificate" => Ok(Value::String(b64_std(&tbs_of_certificate(&bytes_of(input, "cert"))?))),
            "unrecognised_critical_extension" => {
                let rec: Option<HashSet<String>> = input.get("recognised").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(|s| s.to_string()).collect());
                Ok(match unrecognised_critical_extension(&bytes_of(input, "cert"), rec.as_ref())? {
                    Some(o) => Value::String(o),
                    None => Value::Null,
                })
            }
            "check_chain_roles" => {
                let chain: Vec<Vec<u8>> = input.get("chain").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(b64_lenient).collect()).unwrap_or_default();
                Ok(match check_chain_roles(&chain) {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                })
            }
            "der_validity_ms" => {
                let (f, t) = der_validity_ms(&bytes_of(input, "cert"));
                Ok(json!({ "from": f, "to": t }))
            }
            "parse_der_time" => {
                let tag = input.get("tag").and_then(Value::as_u64).unwrap_or(0) as u8;
                let text = input.get("text").and_then(Value::as_str).unwrap_or("");
                Ok(match parse_der_time(tag, text) {
                    Some(t) => json!(t),
                    None => Value::Null,
                })
            }
            other => Err(format!("unknown x509 function {other}")),
        }
    })();
    match r {
        Ok(v) => json!({ "ok": true, "value": v }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}
