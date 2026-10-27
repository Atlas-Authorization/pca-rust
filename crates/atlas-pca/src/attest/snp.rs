//! AMD SEV-SNP: `ATTESTATION_REPORT` parsing, the VCEK -> ASK -> ARK chain (ARK pinned per processor family), the
//! ECDSA-P384 report signature, the VCEK <-> report binding, the acceptance policy and the two binding modes.

use super::der::{find_ext, parse_cert_extensions, parse_tbs_extensions, tbs_of_certificate, der_validity_ms, check_chain_roles, recognised_critical};
use super::util::{b64_lenient, hex_lower, lower_list, sha384, str_array, timing_safe_eq};
use super::x509::{ecdsa_verify_raw, pem_blocks, Cert, EcCurve, PubKey};
use super::{attestation_binding, check_azure_runtime_data_binding, default_measured, AttResult, Binding};
use serde_json::{Map, Value};

pub const AMD_SNP_SUITE: &str = "amd-sev-snp-ecdsa-p384";

/// SPKI SHA-384 (lowercase hex) of each family's ARK.
pub fn ark_pin(family: &str) -> Option<&'static str> {
    match family {
        "milan" => Some("1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e"),
        "genoa" => Some("32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880"),
        "turin" => Some("3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5"),
        _ => None,
    }
}

const REPORT_LEN: usize = 0x4a0;
const SIGNED_END: usize = 0x2a0;
const SIG_R: usize = 0x2a0;
const SIG_S: usize = 0x2e8;

pub struct SnpReport {
    pub guest_svn: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub signature_algo: u32,
    pub reported_tcb: u64,
    pub committed_tcb: u64,
    pub launch_tcb: u64,
    pub report_data: Vec<u8>,
    pub measurement: Vec<u8>,
    pub host_data: Vec<u8>,
    pub chip_id: Vec<u8>,
    r: Vec<u8>,
    s: Vec<u8>,
    signed: Vec<u8>,
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// `parseSevSnpReport`: needs everything up to and including `s` (816 bytes).
pub fn parse_report(b: &[u8]) -> Result<SnpReport, String> {
    let min = SIG_S + 72;
    if b.len() < min {
        return Err(format!("parseSevSnpReport: report too short ({} < {})", b.len(), min));
    }
    Ok(SnpReport {
        guest_svn: u32le(b, 0x004),
        policy: u64le(b, 0x008),
        vmpl: u32le(b, 0x030),
        signature_algo: u32le(b, 0x034),
        reported_tcb: u64le(b, 0x180),
        committed_tcb: u64le(b, 0x1e0),
        launch_tcb: u64le(b, 0x1f0),
        report_data: b[0x050..0x090].to_vec(),
        measurement: b[0x090..0x0c0].to_vec(),
        host_data: b[0x0c0..0x0e0].to_vec(),
        chip_id: b[0x1a0..0x1e0].to_vec(),
        r: b[SIG_R..SIG_R + 72].to_vec(),
        s: b[SIG_S..SIG_S + 72].to_vec(),
        signed: b[..SIGNED_END].to_vec(),
    })
}

/// AMD stores r and s little-endian in 72-byte fields; the P-384 scalars are the low 48 bytes.
fn report_sig_valid(report: &SnpReport, vcek: &PubKey) -> bool {
    let (curve, point) = match vcek {
        PubKey::Ec { curve, point } if *curve == EcCurve::P384 => (*curve, point),
        _ => return false,
    };
    if report.r[48..].iter().any(|x| *x != 0) || report.s[48..].iter().any(|x| *x != 0) {
        return false;
    }
    let mut rs = Vec::with_capacity(96);
    rs.extend(report.r[..48].iter().rev());
    rs.extend(report.s[..48].iter().rev());
    ecdsa_verify_raw(curve, point, &sha384(&report.signed), &rs)
}

const OID_HWID: &str = "1.3.6.1.4.1.3704.1.4";
const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";

fn decode_spl(v: &[u8]) -> Result<i64, &'static str> {
    if v.len() < 3 || v[0] != 0x02 {
        return Err("is not a DER INTEGER");
    }
    let len = v[1] as usize;
    if len < 1 || len > 2 || v.len() != 2 + len {
        return Err("has a wrong-length INTEGER");
    }
    let c0 = v[2];
    if c0 & 0x80 != 0 {
        return Err("is negative");
    }
    if len == 2 {
        if c0 != 0x00 {
            return Err("is out of range (> 255)");
        }
        if v[3] & 0x80 == 0 {
            return Err("is a non-minimal INTEGER");
        }
        return Ok(v[3] as i64);
    }
    Ok(c0 as i64)
}

/// `checkVcekReportBinding`: the VCEK's hwID and SPL extensions must equal the report's chip id and reported TCB.
pub fn check_vcek_report_binding(vcek_tbs: &[u8], report: &SnpReport) -> Option<String> {
    let exts = match parse_tbs_extensions(vcek_tbs) {
        Ok(e) => e,
        Err(e) => return Some(format!("VCEK extensions malformed: {e}")),
    };
    let hw = match find_ext(&exts, OID_HWID) {
        Some(h) => h,
        None => return Some("VCEK certificate has no CHIP_ID (hwID) extension".into()),
    };
    if hw.critical {
        return Some("VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)".into());
    }
    if hw.value.len() != 64 {
        return Some(format!("VCEK CHIP_ID (hwID) extension is {} bytes, expected 64", hw.value.len()));
    }
    if !timing_safe_eq(&hw.value, &report.chip_id) {
        return Some("VCEK CHIP_ID does not match report chip_id".into());
    }
    let t = report.reported_tcb;
    let byte_at = |i: u32| -> i64 { ((t >> (8 * i)) & 0xff) as i64 };
    let pairs: [(&str, &str, i64); 4] = [(OID_BL_SPL, "bootloader", byte_at(0)), (OID_TEE_SPL, "tee", byte_at(1)), (OID_SNP_SPL, "snp", byte_at(6)), (OID_UCODE_SPL, "microcode", byte_at(7))];
    for (oid, name, want) in pairs {
        let ext = match find_ext(&exts, oid) {
            Some(e) => e,
            None => return Some(format!("VCEK certificate has no {name} SPL extension")),
        };
        if ext.critical {
            return Some(format!("VCEK {name} SPL extension is marked critical (the AMD profile is non-critical)"));
        }
        match decode_spl(&ext.value) {
            Err(why) => return Some(format!("VCEK {name} SPL extension {why}")),
            Ok(got) => {
                if got != want {
                    return Some(format!("VCEK {name} SPL {got} does not match report reported_tcb ({want}) \u{2014} TCB downgrade?"));
                }
            }
        }
    }
    None
}

fn wrap_amd(e: String) -> String {
    format!("AMD chain verification error: {e}")
}

/// `verifyAmdCertChain`: the VCEK, ASK and ARK; the ARK pinned. Returns the VCEK key and its tbsCertificate.
fn verify_amd_cert_chain(vcek_der: &[u8], ask_ark_pem: &str, pin: &str, now_ms: f64, skew: Option<f64>) -> Result<(PubKey, Vec<u8>), String> {
    if !now_ms.is_finite() {
        return Err("nowMs (verifier clock) is required for the AMD chain validity check".into());
    }
    let skew = skew.unwrap_or(0.0);
    if !skew.is_finite() || skew < 0.0 {
        return Err("clockSkewMs must be a non-negative number".into());
    }
    let vcek = Cert::from_der(vcek_der).map_err(wrap_amd)?;
    let pems = pem_blocks(ask_ark_pem);
    if pems.len() != 2 {
        return Err("ASK+ARK chain must contain exactly two certificates (ASK then ARK)".into());
    }
    let ask = Cert::from_pem(pems[0]).map_err(wrap_amd)?;
    let ark = Cert::from_pem(pems[1]).map_err(wrap_amd)?;
    let ark_self = ark.subject_string() == ark.issuer_string();
    if !ark_self || !ark.verify(&ark.public_key().map_err(wrap_amd)?) {
        return Err("second certificate of the chain is not a self-signed ARK (chain out of order?)".into());
    }
    if ask.subject_string() == ask.issuer_string() {
        return Err("first certificate of the chain is self-signed, not an ASK (chain out of order?)".into());
    }
    if ask.subject_string() != vcek.issuer_string() {
        return Err("ASK subject does not match the VCEK issuer".into());
    }
    let ark_key = ark.public_key().map_err(wrap_amd)?;
    if ark_key.spki_sha384_hex() != pin.to_lowercase() {
        return Err("ARK does not match the pinned AMD trust anchor".into());
    }
    let ask_key = ask.public_key().map_err(wrap_amd)?;
    if ask.issuer_string() != ark.subject_string() || !ask.verify(&ark_key) {
        return Err("ASK is not signed by ARK".into());
    }
    if !vcek.verify(&ask_key) {
        return Err("VCEK is not signed by ASK".into());
    }

    let ders: [(&str, Vec<u8>, &Cert); 3] = [("VCEK", vcek_der.to_vec(), &vcek), ("ASK", ask.raw.clone(), &ask), ("ARK", ark.raw.clone(), &ark)];
    let plain: Vec<Vec<u8>> = ders.iter().map(|d| d.1.clone()).collect();
    if let Some(role) = check_chain_roles(&plain) {
        return Err(format!("AMD chain role check failed: {role}"));
    }
    let known = recognised_critical();
    for (label, der, cert) in ders.iter() {
        let exts = parse_cert_extensions(der).map_err(wrap_amd)?;
        for e in &exts {
            if e.critical && !known.contains(&e.oid) {
                return Err(format!("{label} certificate has an unrecognised critical extension {}", e.oid));
            }
        }
        if *label != "VCEK" && find_ext(&exts, "2.5.29.19").map(|e| e.critical) != Some(true) {
            return Err(format!("{label} certificate BasicConstraints is not marked critical"));
        }
        let (from, to) = der_validity_ms(&cert.raw);
        let (from, to) = match (from, to) {
            (Some(f), Some(t)) => (f as f64, t as f64),
            _ => return Err(format!("{label} certificate validity is unparseable")),
        };
        if now_ms + skew < from {
            return Err(format!("{label} certificate is not yet valid"));
        }
        if now_ms - skew > to {
            return Err(format!("{label} certificate has expired"));
        }
    }

    let key = vcek.public_key().map_err(wrap_amd)?;
    let ok_curve = matches!(&key, PubKey::Ec { curve, .. } if *curve == EcCurve::P384);
    if !ok_curve {
        let curve = match &key {
            PubKey::Ec { curve, .. } => curve.node_name().unwrap_or("undefined").to_string(),
            _ => "undefined".to_string(),
        };
        return Err(wrap_amd(format!("VCEK is not EC secp384r1 (got {}/{})", key.type_name(), curve)));
    }
    let tbs = tbs_of_certificate(vcek_der).map_err(wrap_amd)?;
    Ok((key, tbs))
}

// ───────────────────────────── policy

#[derive(Clone, Debug)]
enum Vmpl {
    Any,
    N(f64),
    /// A value that is neither a number nor `'any'`: never equal to a report's VMPL.
    Never,
}

#[derive(Clone, Debug)]
pub struct SnpPolicy {
    measurements: Vec<String>,
    host_data: Vec<String>,
    chip_ids: Vec<String>,
    allow_debug: bool,
    min_guest_svn: Option<f64>,
    min_reported_tcb: Option<u64>,
    min_committed_tcb: Option<u64>,
    min_launch_tcb: Option<u64>,
    require_vmpl: Vmpl,
    require_ecdsa_p384: bool,
}

/// `BigInt(v)` of a policy value: a decimal string (or a non-negative integer number).
pub fn parse_u64_policy(v: &Value) -> Result<Option<u64>, String> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(Some(0));
            }
            t.parse::<u64>().map(Some).map_err(|_| format!("Cannot convert {s} to a BigInt"))
        }
        Value::Number(n) => match n.as_u64() {
            Some(u) => Ok(Some(u)),
            None => Err(format!("The number {n} cannot be converted to a BigInt because it is not an integer")),
        },
        _ => Err("Cannot convert value to a BigInt".into()),
    }
}

fn check_policy(report: &SnpReport, p: &SnpPolicy) -> Option<String> {
    if p.require_ecdsa_p384 && report.signature_algo != 1 {
        return Some(format!("unexpected signature_algo {}", report.signature_algo));
    }
    if !p.allow_debug && (report.policy & (1u64 << 19)) != 0 {
        return Some("guest policy has the DEBUG bit set (host can inspect the guest)".into());
    }
    if let Some(min) = p.min_guest_svn {
        if (report.guest_svn as f64) < min {
            return Some(format!("guest_svn {} below minimum {}", report.guest_svn, js_num(min)));
        }
    }
    if let Some(min) = p.min_reported_tcb {
        if report.reported_tcb < min {
            return Some("reported_tcb below minimum (rollback?)".into());
        }
    }
    if let Some(min) = p.min_committed_tcb {
        if report.committed_tcb < min {
            return Some("committed_tcb below minimum (rollback?)".into());
        }
    }
    if let Some(min) = p.min_launch_tcb {
        if report.launch_tcb < min {
            return Some("launch_tcb below minimum".into());
        }
    }
    match &p.require_vmpl {
        Vmpl::Any => {}
        Vmpl::N(n) => {
            if (report.vmpl as f64) != *n {
                return Some(format!("vmpl {} is not the required {}", report.vmpl, js_num(*n)));
            }
        }
        Vmpl::Never => return Some(format!("vmpl {} is not the required value", report.vmpl)),
    }
    if !p.measurements.is_empty() && !p.measurements.contains(&hex_lower(&report.measurement)) {
        return Some("measurement not in policy allowlist".into());
    }
    if !p.host_data.is_empty() && !p.host_data.contains(&hex_lower(&report.host_data)) {
        return Some("host_data not in policy allowlist".into());
    }
    if !p.chip_ids.is_empty() && !p.chip_ids.contains(&hex_lower(&report.chip_id)) {
        return Some("chip_id not in policy allowlist".into());
    }
    None
}

/// A JSON number the way JavaScript prints it (integers without a fraction).
pub fn js_num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e21 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn list_of(p: &Map<String, Value>, k: &str) -> Vec<String> {
    match p.get(k).and_then(str_array) {
        Some(v) => lower_list(&v),
        None => Vec::new(),
    }
}

// ───────────────────────────── the verifier

pub struct SnpVerifier {
    family: String,
    pin: String,
    direct: bool,
    policy: SnpPolicy,
    skew: Option<f64>,
}

impl SnpVerifier {
    /// `createAmdSnpVerifier` from the wire configuration. `Err` is the constructor's refusal.
    pub fn from_config(cfg: &Map<String, Value>) -> Result<SnpVerifier, String> {
        let family = cfg.get("family").and_then(Value::as_str).unwrap_or("");
        let builtin = match ark_pin(family) {
            Some(p) => p,
            None => return Err("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'".into()),
        };
        // the harness pin override replaces the family pin at construction
        let pin = match cfg.get("trustAnchorArkSpkiSha384").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => builtin.to_string(),
        };
        let binding = cfg.get("binding").and_then(Value::as_str);
        if binding != Some("report-data") && binding != Some("azure-runtime-data") {
            return Err("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'".into());
        }
        let empty = Map::new();
        let pol = cfg.get("policy").and_then(Value::as_object).unwrap_or(&empty);
        let meas = pol.get("measurements").and_then(Value::as_array);
        if meas.map_or(true, |m| m.is_empty()) {
            return Err("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)".into());
        }
        let vmpl = match pol.get("requireVmpl") {
            None | Some(Value::Null) => Vmpl::N(0.0),
            Some(Value::String(s)) if s == "any" => Vmpl::Any,
            Some(Value::Number(n)) => Vmpl::N(n.as_f64().unwrap_or(f64::NAN)),
            Some(_) => Vmpl::Never,
        };
        let tcb = |k: &str| -> Result<Option<u64>, String> { pol.get(k).map_or(Ok(None), parse_u64_policy) };
        let policy = SnpPolicy {
            measurements: list_of(pol, "measurements"),
            host_data: list_of(pol, "hostData"),
            chip_ids: list_of(pol, "chipIds"),
            allow_debug: pol.get("allowDebug").and_then(Value::as_bool) == Some(true),
            min_guest_svn: pol.get("minGuestSvn").and_then(Value::as_f64),
            min_reported_tcb: tcb("minReportedTcb")?,
            min_committed_tcb: tcb("minCommittedTcb")?,
            min_launch_tcb: tcb("minLaunchTcb")?,
            require_vmpl: vmpl,
            require_ecdsa_p384: pol.get("requireEcdsaP384").and_then(Value::as_bool) != Some(false),
        };
        Ok(SnpVerifier { family: family.to_string(), pin, direct: binding == Some("report-data"), policy, skew: cfg.get("clockSkewMs").and_then(Value::as_f64) })
    }

    pub fn verify(&self, ev: Option<&Value>, now_ms: i64, expected: Option<&Binding>) -> AttResult {
        let fail = |r: String| AttResult::fail(r);
        let obj = match ev.and_then(Value::as_object) {
            Some(o) => o,
            None => return fail("no AMD SEV-SNP evidence for this action".into()),
        };
        let report_b = obj.get("report").and_then(Value::as_str).map(b64_lenient);
        let vcek_b = obj.get("vcekDer").and_then(Value::as_str).map(b64_lenient);
        let ask_ark = obj.get("askArkPem").and_then(Value::as_str);
        let (report_b, vcek_b, ask_ark) = match (report_b, vcek_b, ask_ark) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return fail("no AMD SEV-SNP evidence for this action".into()),
        };
        let runtime = obj.get("runtimeData").and_then(Value::as_str).map(b64_lenient);
        let expected = match expected {
            Some(e) => e,
            None => return fail("no expected attestation binding supplied".into()),
        };
        let r = match self.verify_genuine(&report_b, &vcek_b, ask_ark, now_ms as f64, if self.direct { Some(expected) } else { None }) {
            Ok(r) => r,
            Err(why) => return fail(format!("SEV-SNP report invalid: {why}")),
        };
        if !self.direct {
            let rt = match &runtime {
                Some(x) => x,
                None => return fail("azure-runtime-data binding needs the runtime-data JSON bytes".into()),
            };
            if let Some(why) = check_azure_runtime_data_binding(&r.report_data, rt, expected) {
                return fail(why);
            }
        }
        AttResult::pass(
            default_measured(&hex_lower(&r.measurement), &hex_lower(&r.chip_id)),
            vec![("attestation_type", "amd-sev-snp".to_string()), ("family", self.family.clone()), ("measurement", hex_lower(&r.measurement))],
        )
    }

    /// `verifyGenuineSevSnpReport`: the reason on failure.
    fn verify_genuine(&self, raw: &[u8], vcek_der: &[u8], ask_ark: &str, now_ms: f64, expected: Option<&Binding>) -> Result<SnpReport, String> {
        let report = parse_report(raw).map_err(|e| format!("report parse failed: {e}"))?;
        if raw.len() != REPORT_LEN {
            return Err(format!("report length {} is not the canonical {}", raw.len(), REPORT_LEN));
        }
        if raw[SIG_S + 72..].iter().any(|b| *b != 0) || raw[SIG_R + 48..SIG_R + 72].iter().any(|b| *b != 0) || raw[SIG_S + 48..SIG_S + 72].iter().any(|b| *b != 0) {
            return Err("report signature block has non-zero reserved bytes".into());
        }
        let (key, tbs) = match verify_amd_cert_chain(vcek_der, ask_ark, &self.pin, now_ms, self.skew) {
            Ok(x) => x,
            Err(e) => return Err(format!("cert chain invalid: {e}")),
        };
        if !report_sig_valid(&report, &key) {
            return Err("report signature does not verify under VCEK".into());
        }
        if let Some(e) = check_vcek_report_binding(&tbs, &report) {
            return Err(e);
        }
        if let Some(exp) = expected {
            let want = match attestation_binding(exp) {
                Ok(w) => w,
                Err(e) => return Err(format!("genuine verification error (fail closed): {e}")),
            };
            if !timing_safe_eq(&want, &report.report_data) {
                return Err("report_data does not bind holder/grant/epoch/nonce".into());
            }
        }
        if let Some(e) = check_policy(&report, &self.policy) {
            return Err(e);
        }
        Ok(report)
    }
}
