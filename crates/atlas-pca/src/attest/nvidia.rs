//! NVIDIA GPU confidential computing: the SPDM `GET_MEASUREMENTS` transcript signed by the device identity key, the
//! device certificate chain pinned to the NVIDIA root, the pinned measurement blocks and the optional collateral hook
//! (reference manifests, firmware policy, CRLs and OCSP).

use super::dcap::{serial_is_revoked, verify_crl};
use super::ocsp::check_chain_ocsp;
use super::rim::{verify_nvidia_rim, VerifiedRim};
use super::util::{b64_lenient, hex_lower, js_truthy, lower_list, sha256, sha384, str_array};
use super::x509::{pem_blocks, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use super::der::{find_ext, parse_cert_extensions, strict_chain_error, x509_valid_at};
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
    u16::from_le_bytes([byte(b, o) as u8, byte(b, o + 1) as u8]) as usize
}
fn u24le(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([byte(b, o) as u8, byte(b, o + 1) as u8, byte(b, o + 2) as u8, 0]) as usize
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
    if let Some(p) = strict_chain_error(&chain.iter().map(|c| c.raw.clone()).collect::<Vec<_>>()) {
        return Err(format!("device chain profile: {p}"));
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
        // golden index 34 is SPDM block 35
        if index == 34 && nvdec_disabled {
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

/// Which non-root chain certificates must be covered by a verified CRL from their issuer (`requireCrlFor`): by default every one
/// that names a CRL distribution point (OID 2.5.29.31). `None` is the policy when CRLs are supplied but not required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequireCrlFor {
    Cdp,
    All,
    /// Chain indices as given on the wire (checked against the chain at verification time).
    Indices(Vec<i64>),
    None,
}

static NO_CRL_COVERAGE: RequireCrlFor = RequireCrlFor::None;

/// A certificate "carries" a CDP when its extensions name 2.5.29.31; one whose extensions cannot be read counts as carrying one
/// (fail closed: a CRL is then demanded).
fn carries_cdp(c: &Cert) -> bool {
    parse_cert_extensions(&c.raw).map_or(true, |exts| find_ext(&exts, "2.5.29.31").is_some())
}

fn crl_required_indices(chain: &[Cert], policy: &RequireCrlFor) -> Result<Vec<usize>, String> {
    let last = chain.len().saturating_sub(1);
    match policy {
        RequireCrlFor::None => Ok(Vec::new()),
        RequireCrlFor::All => Ok((0..last).collect()),
        RequireCrlFor::Cdp => Ok((0..last).filter(|i| carries_cdp(&chain[*i])).collect()),
        RequireCrlFor::Indices(v) => v
            .iter()
            .map(|&i| match usize::try_from(i) {
                Ok(u) if u < last => Ok(u),
                _ => Err(format!("requireCrlFor index {i} is not a non-root chain certificate")),
            })
            .collect(),
    }
}

/// The existing four-argument form: no coverage demand beyond the supplied CRLs (kept for the k05 table tests).
#[cfg(test)]
fn check_chain_revocation(chain: &[Cert], crls: &[Vec<u8>], now_ms: f64, require_issuers: &[String]) -> Result<(), String> {
    check_chain_revocation_for(chain, crls, now_ms, require_issuers, &RequireCrlFor::None)
}

fn check_chain_revocation_for(chain: &[Cert], crls: &[Vec<u8>], now_ms: f64, require_issuers: &[String], require_for: &RequireCrlFor) -> Result<(), String> {
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
        // a CRL can revoke only the certificate its issuer issued: the one just below the issuer
        if let Some(child) = issuer_idx.checked_sub(1).map(|i| &chain[i]) {
            if serial_is_revoked(&revoked, &child.serial_hex()) {
                return Err(format!("chain certificate '{}' is revoked", subj_line(child)));
            }
        }
    }
    for need in require_issuers {
        if !covered.iter().any(|i| chain[*i].subject_string().contains(need.as_str())) {
            return Err(format!("no verified CRL issued by a certificate matching '{need}'"));
        }
    }
    // coverage: a revoked device or intermediate certificate must not slip through because only the root's CRL was supplied
    for i in crl_required_indices(chain, require_for)? {
        if !covered.contains(&(i + 1)) {
            return Err(format!("no verified CRL from the issuer of chain certificate '{}'", subj_line(&chain[i])));
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
    /// `requireCrlFor`: `cdp` (default), `all` or a list of chain indices; applies only when CRLs are required.
    pub require_crl_for: RequireCrlFor,
    pub firmware: Firmware,
}

/// The coverage policy in force: only when CRLs are required (`crl`, `both`, or the legacy default); a CRL set supplied under
/// `ocsp` or `requireCrls: false` is enforced as today, with no coverage demand.
fn effective_crl_policy(cfg: &CollateralConfig) -> &RequireCrlFor {
    match cfg.mode.as_deref() {
        Some("crl") | Some("both") => &cfg.require_crl_for,
        _ => &NO_CRL_COVERAGE,
    }
}

/// JavaScript `String(v)` for the values a config can hold (TS names the offending value in its refusal).
fn js_string(v: &Value, nested: bool) -> String {
    match v {
        Value::Null if nested => String::new(),
        Value::Null => "null".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(|x| js_string(x, true)).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
        other => other.to_string(),
    }
}

/// attest-nvidia-rim.ts: `cdp` | `all` | an array of integers >= 0; anything else is `malformed requireCrlFor '<String(value)>'`.
fn parse_require_crl_for(col: &Map<String, Value>) -> Result<RequireCrlFor, String> {
    let bad = |v: &Value| format!("nvidiaCollateralHook: malformed requireCrlFor '{}'", js_string(v, false));
    match col.get("requireCrlFor") {
        None | Some(Value::Null) => Ok(RequireCrlFor::Cdp), // `opts.requireCrlFor ?? 'cdp'`
        Some(Value::String(s)) if s == "cdp" => Ok(RequireCrlFor::Cdp),
        Some(Value::String(s)) if s == "all" => Ok(RequireCrlFor::All),
        Some(v @ Value::Array(a)) => a
            .iter()
            .map(|x| x.as_i64().or_else(|| x.as_f64().filter(|f| f.fract() == 0.0 && f.abs() < 9e15).map(|f| f as i64)).filter(|i| *i >= 0).ok_or_else(|| bad(v)))
            .collect::<Result<Vec<_>, _>>()
            .map(RequireCrlFor::Indices),
        Some(v) => Err(bad(v)),
    }
}

struct Bundle {
    driver_rim: String,
    vbios_rim: String,
    crls: Vec<Vec<u8>>,
    ocsp: Vec<Vec<u8>>,
}

fn compile_firmware(fw: Option<&Value>) -> Result<Firmware, String> {
    let fw = match fw {
        None | Some(Value::Null) => return Ok(Firmware::default()),
        Some(Value::Object(f)) => f,
        Some(_) => return Err("nvidiaCollateralHook: firmware must be an object".into()),
    };
    let need = |v: &str, radix: u32, what: &str| -> Result<Vec<u64>, String> { parse_version(v, radix).ok_or_else(|| format!("nvidiaCollateralHook: malformed {what} '{v}'")) };
    // a present non-empty minimum must be a string (a number or object would otherwise be skipped silently)
    for k in ["minDriverVersion", "minVbiosVersion"] {
        if let Some(v) = fw.get(k).filter(|v| js_truthy(v) && !v.is_string()) {
            return Err(format!("nvidiaCollateralHook: malformed {k} '{}'", js_string(v, false)));
        }
    }
    let s = |k: &str| fw.get(k).and_then(Value::as_str).filter(|x| !x.is_empty());
    let deny = |k: &str, radix: u32| -> Result<Vec<Vec<u64>>, String> {
        let bad = |v: &Value| format!("nvidiaCollateralHook: malformed {k} entry '{}'", js_string(v, false));
        match fw.get(k) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(a)) => a.iter().map(|v| v.as_str().ok_or_else(|| bad(v)).and_then(|t| need(t, radix, &format!("{k} entry")))).collect(),
            Some(v) => Err(bad(v)),
        }
    };
    let mut out = Firmware::default();
    if let Some(v) = s("minDriverVersion") {
        out.min_driver = Some(need(v, 10, "minDriverVersion")?);
        out.min_driver_text = v.to_string();
    }
    if let Some(v) = s("minVbiosVersion") {
        out.min_vbios = Some(need(v, 16, "minVbiosVersion")?);
        out.min_vbios_text = v.to_string();
    }
    out.deny_driver = deny("denyDriverVersions", 10)?;
    out.deny_vbios = deny("denyVbiosVersions", 16)?;
    Ok(out)
}

impl CollateralConfig {
    /// `nvidiaCollateralHook` options from the wire `collateral` configuration.
    pub fn from_config(col: &Map<String, Value>) -> Result<CollateralConfig, String> {
        let pins = match col.get("rimRootSpkiSha256").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => str_array(&Value::Array(a.clone())).unwrap_or_default(),
            _ => return Err("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root".into()),
        };
        let firmware = compile_firmware(col.get("firmware"))?;
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
        let require_crl_for = parse_require_crl_for(col)?;
        let require_crl_issuers = match col.get("requireCrlIssuers") {
            None | Some(Value::Null) => Vec::new(),
            Some(v) => str_array(v).ok_or_else(|| "nvidiaCollateralHook: requireCrlIssuers must list only strings".to_string())?,
        };
        Ok(CollateralConfig { rim_root_pins: pins, mode, require_crl_issuers, require_crl_for, firmware })
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
        if let Err(r) = check_chain_revocation_for(&chain.chain, &bundle.crls, now_ms, &cfg.require_crl_issuers, effective_crl_policy(cfg)) {
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
        let collateral = match cfg.get("collateral") {
            None | Some(Value::Null) => None,
            Some(Value::Object(c)) => Some(CollateralConfig::from_config(c)?),
            Some(_) => return Err(format!("{pre}: collateral must be an object")),
        };
        let pins = match cfg.get("rootSpkiSha256").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => str_array(&Value::Array(a.clone())).unwrap_or_default(),
            _ => return Err(format!("{pre}: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")),
        };
        let pol = cfg.get("policy").and_then(Value::as_object);
        match pol.and_then(|p| p.get("leafSubjectIncludes")) {
            None | Some(Value::Null) | Some(Value::String(_)) => {}
            Some(_) => return Err(format!("{pre}: policy.leafSubjectIncludes must be a string")),
        }
        let pinned: Vec<(String, String)> = match pol.and_then(|p| p.get("measurements")).and_then(Value::as_object) {
            Some(m) => m.iter().map(|(k, v)| (k.clone(), v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string()))).collect(),
            None => Vec::new(),
        };
        if pinned.is_empty() && collateral.is_none() {
            return Err(format!("{pre}: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"));
        }
        let mut measurements = Vec::new();
        for (k, d) in pinned {
            match pinned_index(&k) {
                Some(i) => measurements.push((i, d.to_lowercase())),
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

/// A `policy.measurements` key: `Number(k)` must be an integer in 0..=255 (attest-nvidia-spdm.ts:317-318).
fn pinned_index(k: &str) -> Option<u8> {
    Some(crate::actions::js_str_to_number(k)).filter(|n| n.fract() == 0.0 && (0.0..=255.0).contains(n)).map(|n| n as u8)
}

#[cfg(test)]
#[path = "k05_nvidia_test.rs"]
mod k05_nvidia_test;

#[cfg(test)]
#[path = "k05e_nvidia_crl_coverage_test.rs"]
mod k05e_nvidia_crl_coverage_test;

#[cfg(test)]
mod pinned_index_tests {
    use super::pinned_index;
    #[test]
    fn a_measurement_index_reads_as_js_number() {
        for (k, want) in [("0", 0), ("255", 255), ("", 0), (" 7 ", 7), ("\u{feff}7", 7), ("0x10", 16), ("1e1", 10), ("-0", 0)] {
            assert_eq!(pinned_index(k), Some(want), "{k:?}");
        }
        for k in ["256", "-1", "1.5", "inf", "nan", "Infinity", "\u{85}7", "1_0", "0x"] {
            assert_eq!(pinned_index(k), None, "{k:?}");
        }
    }
}

#[cfg(test)]
mod firmware_policy_tests {
    use super::{compile_firmware, firmware_check, RimIds};
    #[test]
    fn an_empty_firmware_map_is_a_policy_not_no_policy() {
        let fw = compile_firmware(Some(&serde_json::json!({}))).unwrap();
        let ids = |d: &str, v: &str| RimIds { chip: "GH100".into(), driver_version: d.into(), vbios_version: v.into() };
        assert_eq!(firmware_check(&fw, &ids("x.1", "96.00.88")).as_deref(), Some("driver version 'x.1' in the GPU report is not parseable"));
        assert_eq!(firmware_check(&fw, &ids("550.54", "zz.00")).as_deref(), Some("VBIOS version 'zz.00' in the GPU report is not parseable"));
        assert_eq!(firmware_check(&fw, &ids("550.54", "96.00.88")), None);
    }
}
