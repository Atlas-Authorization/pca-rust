//! Vendor hardware-attestation verifiers: AMD SEV-SNP, Intel TDX (DCAP, with PCS collateral), Azure Attestation, Google
//! Cloud Confidential Space and NVIDIA GPU (SPDM, RIM, CRL and OCSP), plus the strict DER / X.509 readers they share.
//!
//! Build one from a serialisable configuration with [`verifier_from_config`]; hand it the evidence for an action and
//! the binding the evidence must carry. The result is a [`AttResult`]: it is `ok` only when the vendor chain, the
//! signatures, the policy gates and the binding (`holder`, `grant`, `epoch`, `nonce`) all hold. Every failure is a
//! denial with a reason, never a pass.

pub mod der;
pub mod dcap;
pub mod factory;
pub mod gcp;
pub mod jws;
pub mod maa;
pub mod nvidia;
pub mod ocsp;
pub mod rim;
pub mod snp;
pub mod util;
pub mod x509;

use serde_json::{json, Map, Value};
use util::{hex_decode, is_hex, safe_uint, sha256, sha512, timing_safe_eq};

pub use factory::{run_attestation_vector, run_x509_vector, verifier_from_config, HardwareVerifier, Vendor};

/// What the evidence must be bound to (holder key, grant reference, epoch, server nonce).
#[derive(Clone, Debug)]
pub struct Binding {
    pub holder_pub: String,
    pub grant_ref: String,
    /// Kept as a JSON number: a fractional or negative epoch is refused like in every other implementation.
    pub epoch: f64,
    pub nonce: String,
}

const BIND_DOMAIN: &[u8] = b"atlas-pca/attest-bind/v1\0";

fn lp(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// `SHA-512( "atlas-pca/attest-bind/v1\0" || lp(holder) || lp(grant) || u64be(epoch) || lp(nonce) )`.
pub fn attestation_binding(b: &Binding) -> Result<Vec<u8>, String> {
    if b.holder_pub.is_empty() {
        return Err("binding: holderPub required".into());
    }
    if b.grant_ref.is_empty() {
        return Err("binding: grantRef required".into());
    }
    if b.nonce.is_empty() {
        return Err("binding: nonce required".into());
    }
    if !safe_uint(b.epoch) {
        return Err("binding: epoch must be a non-negative safe integer".into());
    }
    let mut buf = BIND_DOMAIN.to_vec();
    lp(&mut buf, &b.holder_pub);
    lp(&mut buf, &b.grant_ref);
    buf.extend_from_slice(&(b.epoch as u64).to_be_bytes());
    lp(&mut buf, &b.nonce);
    Ok(sha512(&buf))
}

/// The verdict of a vendor verifier (the TypeScript `HardwareAttestationResult`).
#[derive(Clone, Debug, Default)]
pub struct AttResult {
    pub ok: bool,
    pub bound: Option<bool>,
    pub reason: Option<String>,
    /// `model_id`, `weights_digest`, `weights_measured`, `runtime_measurement`, `operator` (and overrides).
    pub measured: Option<Map<String, Value>>,
    pub host_asserted: Option<Map<String, Value>>,
}

impl AttResult {
    pub fn fail(reason: impl Into<String>) -> AttResult {
        AttResult { ok: false, reason: Some(reason.into()), ..Default::default() }
    }
    pub fn pass(measured: Map<String, Value>, host: Vec<(&str, String)>) -> AttResult {
        let mut h = Map::new();
        for (k, v) in host {
            h.insert(k.to_string(), Value::String(v));
        }
        AttResult { ok: true, bound: Some(true), reason: None, measured: Some(measured), host_asserted: Some(h) }
    }
    /// The JSON form of the result (`ok`, `bound`, `reason`, `measured`, `hostAsserted`; absent members omitted).
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("ok".into(), Value::Bool(self.ok));
        if let Some(b) = self.bound {
            m.insert("bound".into(), Value::Bool(b));
        }
        if let Some(r) = &self.reason {
            m.insert("reason".into(), Value::String(r.clone()));
        }
        if let Some(x) = &self.measured {
            m.insert("measured".into(), Value::Object(x.clone()));
        }
        if let Some(x) = &self.host_asserted {
            m.insert("hostAsserted".into(), Value::Object(x.clone()));
        }
        Value::Object(m)
    }
}

/// The default measured identity of a verifier: nothing but the runtime measurement (and operator) the hardware attests.
pub fn default_measured(runtime_measurement: &str, operator: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("model_id".into(), json!(""));
    m.insert("weights_digest".into(), json!(""));
    m.insert("weights_measured".into(), json!(false));
    m.insert("runtime_measurement".into(), json!(runtime_measurement));
    m.insert("operator".into(), json!(operator));
    m
}

/// Azure runtime-data binding: `report_data[0:32] == sha256(runtime data)`, `report_data[32:64] == 0`, and the guest's 64-byte
/// `user-data` inside the runtime-data JSON equals the binding. `None` when it holds, else the failure reason.
pub fn check_azure_runtime_data_binding(report_data: &[u8], runtime_data: &[u8], expected: &Binding) -> Option<String> {
    if report_data.len() != 64 {
        return Some("report_data is not 64 bytes".into());
    }
    if !report_data[32..].iter().all(|b| *b == 0) {
        return Some("report_data[32:64] is not zero (not an Azure runtime-data hash)".into());
    }
    if !timing_safe_eq(&sha256(runtime_data), &report_data[..32]) {
        return Some("sha256(runtime data) does not equal the quote report_data".into());
    }
    let text = String::from_utf8_lossy(runtime_data).to_string();
    let parsed: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Some("runtime data is not valid JSON".into()),
    };
    let obj = match parsed.as_object() {
        Some(o) => o,
        None => return Some("runtime data is not a JSON object".into()),
    };
    let user_data = match obj.get("user-data").and_then(Value::as_str) {
        Some(u) if u.chars().count() == 128 && is_hex(u) => u,
        _ => return Some("runtime data carries no 64-byte hex user-data".into()),
    };
    let want = match attestation_binding(expected) {
        Ok(w) => w,
        Err(e) => return Some(format!("binding not constructible: {e}")),
    };
    match hex_decode(user_data) {
        Some(got) if got == want => None,
        _ => Some("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound quote)".into()),
    }
}
