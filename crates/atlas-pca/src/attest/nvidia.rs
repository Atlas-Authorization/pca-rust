//! NVIDIA GPU confidential computing: the SPDM `GET_MEASUREMENTS` transcript signed by the device identity key, the
//! device certificate chain pinned to the NVIDIA root, the pinned measurement blocks and the optional collateral hook
//! (reference manifests, firmware policy, CRLs and OCSP).

use super::dcap::{serial_is_revoked, verify_crl};
use super::ocsp::check_chain_ocsp;
use super::rim::{verify_nvidia_rim, VerifiedRim};
use super::util::{b64_lenient, hex_lower, lower_list, sha256, sha384, str_array};
use super::x509::{pem_blocks, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use super::der::x509_valid_at;
use super::{attestation_binding, AttResult, Binding};
use serde_json::{Map, Value};
use std::collections::HashMap;

const REQ_LEN: usize = 37;
const NONCE_LEN: usize = 32;
const SIG_LEN: usize = 96;
const MAX_CHAIN: usize = 5;

pub struct Spdm {
    pub request_version: u8,
    pub response_version: u8,
    pub request_nonce: Vec<u8>,
    pub measurements: Vec<(u8, Vec<u8>)>,
    pub opaque: HashMap<u16, Vec<u8>>,
    pub signature: Vec<u8>,
    pub signed: Vec<u8>,
}

fn byte(b: &[u8], o: usize) -> usize {
    b.get(o).copied().unwrap_or(0) as usize
}
fn u16le(b: &[u8], o: usize) -> usize {
    byte(b, o) | byte(b, o + 1) << 8
}
fn u24le(b: &[u8], o: usize) -> usize {
    byte(b, o) | byte(b, o + 1) << 8 | byte(b, o + 2) << 16
}

/// `None` when the request version is >= 0x11 and the response echoes it.
pub fn spdm_version_reason(r: &Spdm) -> Option<String> {
    if r.request_version >= 0x11 && r.response_version == r.request_version {
        return None;
    }
    Some(format!("SPDM version 0x{:x}/0x{:x} is not an accepted GET_MEASUREMENTS version", r.request_version, r.response_version))
}

/// `parseNvidiaSpdmEvidence`.
pub fn parse_spdm(bytes: &[u8]) -> Result<Spdm, String> {
    let pre = "parseNvidiaSpdmEvidence";
    if bytes.len() < REQ_LEN + 8 + NONCE_LEN + 2 + SIG_LEN {
        return Err(format!("{pre}: transcript too short ({})", bytes.len()));
    }
    let code = bytes[1];
    if code != 0xe0 {
        return Err(format!("{pre}: request code 0x{code:x} is not GET_MEASUREMENTS"));
    }
    let request_nonce = bytes[4..4 + NONCE_LEN].to_vec();
    let r = &bytes[REQ_LEN..];
    if byte(r, 1) != 0x60 {
        return Err(format!("{pre}: response code is not MEASUREMENTS"));
    }
    let num_blocks = byte(r, 4);
    let rec_len = u24le(r, 5);
    let mut o = 8usize;
    if o + rec_len + NONCE_LEN + 2 + SIG_LEN > r.len() {
        return Err(format!("{pre}: measurement record length overruns transcript"));
    }
    let mut measurements: Vec<(u8, Vec<u8>)> = Vec::new();
    let rec_end = o + rec_len;
    while o < rec_end {
        if o + 4 > rec_end {
            return Err(format!("{pre}: truncated measurement block header"));
        }
        let index = byte(r, o) as u8;
        let size = u16le(r, o + 2);
        let body = o + 4;
        if body + size > rec_end || size < 3 {
            return Err(format!("{pre}: measurement block overruns record"));
        }
        let vsize = u16le(r, body + 1);
        if 3 + vsize > size {
            return Err(format!("{pre}: DMTF value overruns measurement block"));
        }
        let end = (body + 3 + vsize).min(r.len());
        measurements.push((index, r[(body + 3).min(end)..end].to_vec()));
        o = body + size;
    }
    if measurements.len() != num_blocks {
        return Err(format!("{pre}: header says {num_blocks} blocks, parsed {}", measurements.len()));
    }
    o += NONCE_LEN;
    let opaque_len = u16le(r, o);
    o += 2;
    if o + opaque_len + SIG_LEN != r.len() {
        return Err(format!("{pre}: opaque length + signature do not exactly fill the transcript"));
    }
    let mut opaque: HashMap<u16, Vec<u8>> = HashMap::new();
    let opaque_end = o + opaque_len;
    while o < opaque_end {
        if o + 4 > opaque_end {
            return Err(format!("{pre}: truncated opaque TLV header"));
        }
        let t = u16le(r, o) as u16;
        let l = u16le(r, o + 2);
        o += 4;
        if o + l > opaque_end {
            return Err(format!("{pre}: opaque TLV overruns opaque data"));
        }
        opaque.insert(t, r[o..o + l].to_vec());
        o += l;
    }
    Ok(Spdm { request_version: bytes[0], response_version: r[0], request_nonce, measurements, opaque, signature: r[r.len() - SIG_LEN..].to_vec(), signed: bytes[..bytes.len() - SIG_LEN].to_vec() })
}

/// JavaScript `String.prototype.slice` on an ASCII string.
fn js_slice(s: &str, start: i64, end: i64) -> String {
    let n = s.len() as i64;
    let norm = |v: i64| if v < 0 { (n + v).max(0) } else { v.min(n) };
    let (a, b) = (norm(start), norm(end));
    if a >= b {
        String::new()
    } else {
        s[a as usize..b as usize].to_string()
    }
}

/// NVIDIA's VBIOS version rendering: byte-reverse, then re-pair as dotted hex.
pub fn format_vbios_version(raw: &[u8]) -> String {
    let rev: Vec<u8> = raw.iter().rev().copied().collect();
    let hex = hex_lower(&rev);
    let half = (hex.len() / 2) as i64;
    let temp = js_slice(&hex, half, hex.len() as i64) + &js_slice(&hex, half - 2, half);
    temp.as_bytes().chunks(2).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join(".")
}

pub struct NvChain {
    pub leaf: Cert,
    pub chain: Vec<Cert>,
}

fn is_p384(k: &PubKey) -> bool {
    matches!(k, PubKey::Ec { curve, .. } if *curve == EcCurve::P384)
}

/// `verifyNvidiaDeviceChain`: every link signature-verified, every issuer a CA, every certificate inside its validity
/// window, the root self-signed and pinned by SPKI SHA-256.
pub fn verify_device_chain(pem: &str, root_pins: &[String], now_ms: f64) -> Result<NvChain, String> {
    let blocks = pem_blocks(pem);
    if blocks.is_empty() {
        return Err("device chain unparseable: parsePemChain: no certificates found".into());
    }
    if blocks.len() > MAX_CHAIN {
        return Err(format!("device chain unparseable: parsePemChain: chain longer than {MAX_CHAIN}"));
    }
    let mut chain: Vec<Cert> = Vec::new();
    for b in &blocks {
        chain.push(Cert::from_pem(b).map_err(|e| format!("device chain unparseable: {e}"))?);
    }
    let mut keys: Vec<PubKey> = Vec::new();
    for (i, c) in chain.iter().enumerate() {
        if !x509_valid_at(&c.raw, now_ms, 0.0) {
            return Err(format!("device chain cert #{i} is outside its validity window"));
        }
        let k = c.public_key().map_err(|e| format!("device chain unparseable: {e}"))?;
        if !is_p384(&k) {
            return Err(format!("device chain cert #{i} is not an ECDSA P-384 key"));
        }
        keys.push(k);
    }
    for i in 0..chain.len() - 1 {
        if !chain[i + 1].is_ca() {
            return Err(format!("device chain cert #{} issues a certificate but is not a CA", i + 1));
        }
        if !chain[i].verify(&keys[i + 1]) {
            return Err(format!("device chain link #{i} signature does not verify under its issuer"));
        }
    }
    let last = chain.len() - 1;
    if !chain[last].is_ca() || !chain[last].verify(&keys[last]) {
        return Err("device chain root is not a self-signed CA".into());
    }
    let pins = lower_list(root_pins);
    if !pins.contains(&keys[last].spki_sha256_hex()) {
        return Err("chain root is not a pinned NVIDIA root".into());
    }
    Ok(NvChain { leaf: chain[0].clone(), chain })
}

// ───────────────────────────── RIM ids, comparison, revocation, firmware policy

fn ascii(b: Option<&Vec<u8>>) -> String {
    let s: String = b.map(|v| v.iter().map(|c| *c as char).collect()).unwrap_or_default();
    s.trim_end_matches('\0').trim().to_string()
}

pub struct RimIds {
    pub chip: String,
    pub driver_version: String,
    pub vbios_version: String,
}

/// `nvidiaRimIdsForReport`: `None` when the GPU report does not name its RIMs.
pub fn rim_ids_for_report(s: &Spdm) -> Option<RimIds> {
    let o = &s.opaque;
    let driver_version = ascii(o.get(&3));
    let vb = o.get(&6);
    let project = ascii(o.get(&17)).to_uppercase();
    let project_sku = ascii(o.get(&18)).to_uppercase();
    let chip_sku = ascii(o.get(&15)).to_uppercase();
    if driver_version.is_empty() || vb.is_none() || project.is_empty() || project_sku.is_empty() || chip_sku.is_empty() {
        return None;
    }
    let mut chip = "GH100".to_string();
    if let Some(raw) = o.get(&35) {
        chip = ascii(Some(raw));
        let b = chip.as_bytes();
        let ok = (3..=12).contains(&b.len()) && b[0].is_ascii_uppercase() && b[1..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
        if !ok {
            return None;
        }
    }
    Some(RimIds { chip, driver_version, vbios_version: format_vbios_version(vb.map(|v| v.as_slice()).unwrap_or(&[])) })
}

fn compare_report_to_rims(s: &Spdm, driver: &VerifiedRim, vbios: &VerifiedRim) -> Result<(), String> {
    let mut merged: Vec<(i64, &super::rim::Golden)> = Vec::new();
    for g in driver.golden.values().filter(|g| g.active) {
        merged.push((g.index, g));
    }
    for g in vbios.golden.values().filter(|g| g.active) {
        if merged.iter().any(|m| m.0 == g.index) {
            return Err(format!("driver and VBIOS RIMs both have an active measurement at index {}", g.index));
        }
        merged.push((g.index, g));
    }
    if merged.is_empty() {
        return Err("RIMs carry no active golden measurements".into());
    }
    let mut runtime: HashMap<i64, &Vec<u8>> = HashMap::new();
    for (idx, d) in &s.measurements {
        runtime.insert(*idx as i64 - 1, d);
    }
    if merged.len() > runtime.len() {
        return Err("RIMs list more active measurements than the report carries".into());
    }
    let nvdec_disabled = s.opaque.get(&11).map_or(false, |v| !v.is_empty() && v[0] == 0x55);
    merged.sort_by_key(|m| m.0);
    let mut mismatches = 0usize;
    for (index, g) in merged {
        if index + 1 == 35 && nvdec_disabled {
            continue;
        }
        let digest = runtime.get(&index);
        let hex = digest.map(|d| hex_lower(d)).unwrap_or_default();
        let bad = match digest {
            None => true,
            Some(d) => d.len() != g.size || !g.hashes.contains(&hex),
        };
        if bad {
            mismatches += 1;
        }
    }
    if mismatches > 0 {
        return Err(format!("runtime measurements differ from the golden RIM values at {mismatches} index(es)"));
    }
    Ok(())
}

fn subj_line(c: &Cert) -> String {
    c.subject_string().replace('\n', ", ")
}

fn check_chain_revocation(chain: &[Cert], crls: &[Vec<u8>], now_ms: f64, require_issuers: &[String]) -> Result<(), String> {
    if crls.is_empty() {
        return Err("no CRLs supplied".into());
    }
    let mut covered: Vec<usize> = Vec::new();
    for (ci, crl) in crls.iter().enumerate() {
        let mut issuer_idx: Option<usize> = None;
        let mut revoked: Vec<String> = Vec::new();
        let mut last_reason = "no chain certificate verifies it".to_string();
        for (i, cert) in chain.iter().enumerate() {
            let key = match cert.public_key() {
                Ok(k) => k,
                Err(e) => return Err(e),
            };
            match verify_crl(crl, &key, now_ms) {
                Ok(r) => {
                    issuer_idx = Some(i);
                    revoked = r;
                    break;
                }
                Err(r) => {
                    if last_reason == "no chain certificate verifies it" || last_reason.contains("signature does not verify") {
                        last_reason = r;
                    }
                }
            }
        }
        let issuer_idx = match issuer_idx {
            Some(i) => i,
            None => return Err(format!("CRL #{ci} rejected: {last_reason}")),
        };
        if !covered.contains(&issuer_idx) {
            covered.push(issuer_idx);
        }
        for i in 0..chain.len() - 1 {
            if i + 1 == issuer_idx && serial_is_revoked(&revoked, &chain[i].serial_hex()) {
                return Err(format!("chain certificate '{}' is revoked", subj_line(&chain[i])));
            }
        }
    }
    for need in require_issuers {
        if !covered.iter().any(|i| chain[*i].subject_string().contains(need.as_str())) {
            return Err(format!("no verified CRL issued by a certificate matching '{need}'"));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
pub struct Firmware {
    pub min_driver: Option<Vec<u64>>,
    pub min_driver_text: String,
    pub min_vbios: Option<Vec<u64>>,
    pub min_vbios_text: String,
    pub deny_driver: Vec<Vec<u64>>,
    pub deny_vbios: Vec<Vec<u64>>,
}

fn parse_version(v: &str, radix: u32) -> Option<Vec<u64>> {
    let parts: Vec<&str> = v.split('.').collect();
    let mut out = Vec::new();
    for p in parts {
        let ok = if radix == 10 { !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) } else { (1..=4).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_hexdigit()) };
        if !ok {
            return None;
        }
        out.push(u64::from_str_radix(p, radix).ok()?);
    }
    Some(out)
}

fn cmp_version(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

fn firmware_check(fw: &Firmware, ids: &RimIds) -> Option<String> {
    let d = match parse_version(&ids.driver_version, 10) {
        Some(d) => d,
        None => return Some(format!("driver version '{}' in the GPU report is not parseable", ids.driver_version)),
    };
    let v = match parse_version(&ids.vbios_version, 16) {
        Some(v) => v,
        None => return Some(format!("VBIOS version '{}' in the GPU report is not parseable", ids.vbios_version)),
    };
    if let Some(m) = &fw.min_driver {
        if cmp_version(&d, m).is_lt() {
            return Some(format!("driver {} is below the minimum {}", ids.driver_version, fw.min_driver_text));
        }
    }
    if let Some(m) = &fw.min_vbios {
        if cmp_version(&v, m).is_lt() {
            return Some(format!("VBIOS {} is below the minimum {}", ids.vbios_version, fw.min_vbios_text));
        }
    }
    if fw.deny_driver.iter().any(|x| cmp_version(&d, x).is_eq()) {
        return Some(format!("driver {} is on the deny list", ids.driver_version));
    }
    if fw.deny_vbios.iter().any(|x| cmp_version(&v, x).is_eq()) {
        return Some(format!("VBIOS {} is on the deny list", ids.vbios_version));
    }
    None
}

#[derive(Clone, Debug)]
pub struct CollateralConfig {
    pub rim_root_pins: Vec<String>,
    /// `crl`, `ocsp`, `both` or none.
    pub mode: Option<String>,
    pub require_crl_issuers: Vec<String>,
    pub firmware: Firmware,
}

struct Bundle {
    driver_rim: String,
    vbios_rim: String,
    crls: Vec<Vec<u8>>,
    ocsp: Vec<Vec<u8>>,
}

fn compile_firmware(fw: Option<&Map<String, Value>>) -> Result<Firmware, String> {
    let fw = match fw {
        Some(f) => f,
        None => return Ok(Firmware::default()),
    };
    let need = |v: &str, radix: u32, what: &str| -> Result<Vec<u64>, String> { parse_version(v, radix).ok_or_else(|| format!("nvidiaCollateralHook: malformed {what} '{v}'")) };
    let s = |k: &str| fw.get(k).and_then(Value::as_str).filter(|x| !x.is_empty());
    let mut out = Firmware::default();
    if let Some(v) = s("minDriverVersion") {
        out.min_driver = Some(need(v, 10, "minDriverVersion")?);
        out.min_driver_text = v.to_string();
    }
    if let Some(v) = s("minVbiosVersion") {
        out.min_vbios = Some(need(v, 16, "minVbiosVersion")?);
        out.min_vbios_text = v.to_string();
    }
    for v in fw.get("denyDriverVersions").and_then(str_array).unwrap_or_default() {
        out.deny_driver.push(need(&v, 10, "denyDriverVersions entry")?);
    }
    for v in fw.get("denyVbiosVersions").and_then(str_array).unwrap_or_default() {
        out.deny_vbios.push(need(&v, 16, "denyVbiosVersions entry")?);
    }
    Ok(out)
}

impl CollateralConfig {
    /// `nvidiaCollateralHook` options from the wire `collateral` configuration.
    pub fn from_config(col: &Map<String, Value>) -> Result<CollateralConfig, String> {
        let pins = match col.get("rimRootSpkiSha256").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => str_array(&Value::Array(a.clone())).unwrap_or_default(),
            _ => return Err("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root".into()),
        };
        let firmware = compile_firmware(col.get("firmware").and_then(Value::as_object))?;
        let mode = match col.get("revocation").and_then(Value::as_str) {
            Some(m) => Some(m.to_string()),
            None => {
                if col.get("requireCrls").and_then(Value::as_bool) == Some(false) {
                    None
                } else {
                    Some("crl".to_string())
                }
            }
        };
        Ok(CollateralConfig { rim_root_pins: pins, mode, require_crl_issuers: col.get("requireCrlIssuers").and_then(str_array).unwrap_or_default(), firmware })
    }
}

/// Does `subject` contain `chip` delimited by non-alphanumerics (or the string ends)?
fn chip_in_subject(subject: &str, chip: &str) -> bool {
    let s = subject.as_bytes();
    let c = chip.as_bytes();
    if c.is_empty() || s.len() < c.len() {
        return false;
    }
    (0..=s.len() - c.len()).any(|i| {
        &s[i..i + c.len()] == c && (i == 0 || !s[i - 1].is_ascii_alphanumeric()) && (i + c.len() == s.len() || !s[i + c.len()].is_ascii_alphanumeric())
    })
}

/// The collateral `postVerify` hook: `Some(reason)` rejects.
fn collateral_hook(cfg: &CollateralConfig, spdm: &Spdm, chain: &NvChain, bundle: Option<&Bundle>, now_ms: f64) -> Option<String> {
    let ids = match rim_ids_for_report(spdm) {
        Some(i) => i,
        None => return Some("GPU report does not carry the opaque fields needed to name its RIMs".into()),
    };
    let subject = chain.leaf.subject_string();
    if !chip_in_subject(&subject, &ids.chip) {
        return Some(format!("device leaf subject '{}' is not a {} device certificate (chip family mismatch)", subject.replace('\n', ", "), ids.chip));
    }
    if let Some(why) = firmware_check(&cfg.firmware, &ids) {
        return Some(format!("firmware policy: {why}"));
    }
    let bundle = match bundle {
        Some(b) => b,
        None => return Some("no RIM collateral supplied for this report".into()),
    };
    let d = verify_nvidia_rim(&bundle.driver_rim, &cfg.rim_root_pins, now_ms);
    let v = verify_nvidia_rim(&bundle.vbios_rim, &cfg.rim_root_pins, now_ms);
    let d = match d {
        Ok(x) => x,
        Err(r) => return Some(format!("driver RIM: {r}")),
    };
    let v = match v {
        Ok(x) => x,
        Err(r) => return Some(format!("VBIOS RIM: {r}")),
    };
    if d.product != ids.chip {
        return Some(format!("driver RIM product '{}' does not match the GPU chip '{}' (wrong-family manifest)", d.product, ids.chip));
    }
    if v.product != ids.chip {
        return Some(format!("VBIOS RIM product '{}' does not match the GPU chip '{}' (wrong-family manifest)", v.product, ids.chip));
    }
    if d.version != ids.driver_version {
        return Some(format!("driver RIM version '{}' does not match the report's driver '{}'", d.version, ids.driver_version));
    }
    if v.version.replace('.', "").to_uppercase() != ids.vbios_version.replace('.', "").to_uppercase() {
        return Some(format!("VBIOS RIM version '{}' does not match the report's VBIOS '{}'", v.version, ids.vbios_version));
    }
    if let Err(r) = compare_report_to_rims(spdm, &d, &v) {
        return Some(r);
    }
    let mode = cfg.mode.as_deref();
    if !bundle.crls.is_empty() || mode == Some("crl") || mode == Some("both") {
        if let Err(r) = check_chain_revocation(&chain.chain, &bundle.crls, now_ms, &cfg.require_crl_issuers) {
            return Some(format!("revocation: {r}"));
        }
    }
    if !bundle.ocsp.is_empty() || mode == Some("ocsp") || mode == Some("both") {
        if let Err(r) = check_chain_ocsp(&chain.chain, &bundle.ocsp, now_ms) {
            return Some(format!("revocation (OCSP): {r}"));
        }
    }
    None
}

// ───────────────────────────── the verifier

pub struct NvidiaVerifier {
    root_pins: Vec<String>,
    measurements: Vec<(u8, String)>,
    leaf_subject_includes: Option<String>,
    collateral: Option<CollateralConfig>,
}

impl NvidiaVerifier {
    pub fn from_config(cfg: &Map<String, Value>) -> Result<NvidiaVerifier, String> {
        let pre = "createNvidiaSpdmVerifier";
        let collateral = match cfg.get("collateral").and_then(Value::as_object) {
            Some(c) => Some(CollateralConfig::from_config(c)?),
            None => None,
        };
        let pins = match cfg.get("rootSpkiSha256").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => str_array(&Value::Array(a.clone())).unwrap_or_default(),
            _ => return Err(format!("{pre}: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")),
        };
        let pol = cfg.get("policy").and_then(Value::as_object);
        let pinned: Vec<(String, String)> = match pol.and_then(|p| p.get("measurements")).and_then(Value::as_object) {
            Some(m) => m.iter().map(|(k, v)| (k.clone(), v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string()))).collect(),
            None => Vec::new(),
        };
        if pinned.is_empty() && collateral.is_none() {
            return Err(format!("{pre}: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"));
        }
        let mut measurements = Vec::new();
        for (k, d) in pinned {
            let idx = k.trim().parse::<f64>().ok().filter(|n| n.fract() == 0.0 && (0.0..=255.0).contains(n));
            match idx {
                Some(i) => measurements.push((i as u8, d.to_lowercase())),
                None => return Err(format!("{pre}: measurement index out of range")),
            }
        }
        Ok(NvidiaVerifier {
            root_pins: pins,
            measurements,
            leaf_subject_includes: pol.and_then(|p| p.get("leafSubjectIncludes")).and_then(Value::as_str).filter(|s| !s.is_empty()).map(|s| s.to_string()),
            collateral,
        })
    }

    pub fn verify(&self, ev: Option<&Value>, now_ms: i64, expected: Option<&Binding>) -> AttResult {
        let obj = match ev.and_then(Value::as_object) {
            Some(o) => o,
            None => return AttResult::fail("no NVIDIA GPU evidence for this action"),
        };
        let (evidence, chain_pem) = match (obj.get("evidence").and_then(Value::as_str), obj.get("certChainPem").and_then(Value::as_str)) {
            (Some(e), Some(c)) => (b64_lenient(e), c),
            _ => return AttResult::fail("no NVIDIA GPU evidence for this action"),
        };
        let now = now_ms as f64;
        let chain = match verify_device_chain(chain_pem, &self.root_pins, now) {
            Ok(c) => c,
            Err(r) => return AttResult::fail(r),
        };
        let subject = chain.leaf.subject_string();
        if let Some(inc) = &self.leaf_subject_includes {
            if !subject.contains(inc.as_str()) {
                return AttResult::fail(format!("device leaf subject does not contain '{inc}'"));
            }
        }
        let report = match parse_spdm(&evidence) {
            Ok(r) => r,
            Err(e) => return AttResult::fail(format!("GPU attestation report parse failed: {e}")),
        };
        // SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree
        if let Some(reason) = spdm_version_reason(&report) {
            return AttResult::fail(reason);
        }
        let leaf_key = match chain.leaf.public_key() {
            Ok(k) => k,
            Err(e) => return AttResult::fail(format!("nvidia-spdm verification error (fail closed): {e}")),
        };
        if !verify_p1363_sig(&leaf_key, Hash::Sha384, &report.signed, &report.signature) {
            return AttResult::fail("GPU attestation report signature does not verify under the device identity key");
        }
        let expected = match expected {
            Some(e) => e,
            None => return AttResult::fail("no expected attestation binding supplied"),
        };
        let challenge = match attestation_binding(expected) {
            Ok(b) => sha256(&b),
            Err(e) => return AttResult::fail(format!("binding not constructible: {e}")),
        };
        if report.request_nonce != challenge {
            return AttResult::fail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)");
        }
        let mut by_index: HashMap<u8, &Vec<u8>> = HashMap::new();
        for (i, d) in &report.measurements {
            by_index.insert(*i, d);
        }
        for (idx, want) in &self.measurements {
            match by_index.get(idx) {
                None => return AttResult::fail(format!("measurement block {idx} missing from report")),
                Some(m) => {
                    if hex_lower(m) != *want {
                        return AttResult::fail(format!("measurement block {idx} does not match the pinned digest"));
                    }
                }
            }
        }
        if let Some(cc) = &self.collateral {
            let bundle = obj.get("collateral").and_then(Value::as_object).map(|c| Bundle {
                driver_rim: c.get("driverRimXml").and_then(Value::as_str).unwrap_or("").to_string(),
                vbios_rim: c.get("vbiosRimXml").and_then(Value::as_str).unwrap_or("").to_string(),
                crls: c.get("crls").and_then(str_array).unwrap_or_default().iter().map(|s| b64_lenient(s)).collect(),
                ocsp: c.get("ocsp").and_then(str_array).unwrap_or_default().iter().map(|s| b64_lenient(s)).collect(),
            });
            if let Some(why) = collateral_hook(cc, &report, &chain, bundle.as_ref(), now) {
                return AttResult::fail(why);
            }
        }
        let mut ordered: Vec<&(u8, Vec<u8>)> = report.measurements.iter().collect();
        ordered.sort_by_key(|m| m.0);
        let mut all: Vec<u8> = Vec::new();
        for m in ordered {
            all.extend_from_slice(&m.1);
        }
        let mut host: Vec<(&str, String)> = vec![("attestation_type", "nvidia-gpu-cc".to_string()), ("gpu_measurements_sha384", hex_lower(&sha384(&all))), ("leaf_subject", subject.replace('\n', ", "))];
        if let Some(d) = report.opaque.get(&3) {
            host.push(("driver_version", String::from_utf8_lossy(d).trim_end_matches('\0').to_string()));
        }
        if let Some(v) = report.opaque.get(&6) {
            host.push(("vbios_version", format_vbios_version(v)));
        }
        AttResult::pass(super::default_measured("", ""), host)
    }
}
