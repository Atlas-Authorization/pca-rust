//! Intel TDX (DCAP v4 / ECDSA-P256) quotes: the PCK chain to the pinned Intel SGX Root CA, the QE report and attestation
//! key endorsement, the TD quote signature, the policy gates, the two binding modes and the Intel PCS collateral
//! (signed TCB info and QE identity, CRLs, TCB status evaluation).

use super::der::{check_chain_roles, unrecognised_critical_extension, x509_valid_at};
use super::util::{b64_lenient, hex_decode, hex_lower, is_hex, lower_list, parse_iso_ms, sha256, str_array, timing_safe_eq};
use super::x509::{ec_point_valid, ecdsa_verify_raw, pem_blocks, verify_der_sig, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use super::{attestation_binding, check_azure_runtime_data_binding, AttResult, Binding};
use serde_json::{Map, Value};

pub const INTEL_SGX_ROOT_CA_SPKI_SHA256: &str = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e";

const HEADER_LEN: usize = 48;
const TD_REPORT_LEN: usize = 584;
const SGX_REPORT_LEN: usize = 384;
const QE_ATTRIBUTES_OFF: usize = 48;
const QE_REPORT_DATA_OFF: usize = 0x140;

pub struct DcapQuote {
    header: Vec<u8>,
    td_report_body: Vec<u8>,
    quote_signature: Vec<u8>,
    ak_pub_raw: Vec<u8>,
    qe_report_body: Vec<u8>,
    qe_report_signature: Vec<u8>,
    qe_auth_data: Vec<u8>,
    pck_chain_pem: String,
}

fn u16le(b: &[u8], o: usize) -> usize {
    b[o] as usize | (b[o + 1] as usize) << 8
}
fn u32le(b: &[u8], o: usize) -> usize {
    b[o] as usize | (b[o + 1] as usize) << 8 | (b[o + 2] as usize) << 16 | (b[o + 3] as usize) << 24
}

/// `parseDcapQuote`: bounds-checked; trailing bytes after the declared signature data must be zero.
pub fn parse_dcap_quote(q: &[u8]) -> Result<DcapQuote, String> {
    if q.len() < HEADER_LEN + TD_REPORT_LEN + 4 {
        return Err("parseDcapQuote: too short for header + TD report + sig length".into());
    }
    let version = u16le(q, 0);
    let att = u16le(q, 2);
    let tee = u32le(q, 4);
    if version != 4 {
        return Err(format!("parseDcapQuote: unsupported quote version {version} (expected 4)"));
    }
    if att != 2 {
        return Err(format!("parseDcapQuote: unsupported attestation key type {att} (expected ECDSA-P256 = 2)"));
    }
    if tee != 0x81 {
        return Err(format!("parseDcapQuote: unexpected TEE type 0x{tee:x} (expected TDX = 0x81)"));
    }
    let header = q[..HEADER_LEN].to_vec();
    let td = q[HEADER_LEN..HEADER_LEN + TD_REPORT_LEN].to_vec();
    let mut o = HEADER_LEN + TD_REPORT_LEN;
    let sig_len = u32le(q, o);
    o += 4;
    let sig_end = o + sig_len;
    if sig_end > q.len() {
        return Err(format!("parseDcapQuote: signature data ({sig_len}) overruns the quote"));
    }
    let need = |o: usize, n: usize, what: &str| -> Result<(), String> {
        if o + n > sig_end {
            Err(format!("parseDcapQuote: truncated reading {what}"))
        } else {
            Ok(())
        }
    };
    need(o, 64, "quote signature")?;
    let quote_signature = q[o..o + 64].to_vec();
    o += 64;
    need(o, 64, "attestation public key")?;
    let ak_pub_raw = q[o..o + 64].to_vec();
    o += 64;
    need(o, 6, "outer cert-data header")?;
    let outer_type = u16le(q, o);
    let outer_size = u32le(q, o + 2);
    o += 6;
    if outer_type != 6 {
        return Err(format!("parseDcapQuote: outer cert-data type {outer_type} (expected QE-report-cert-data = 6)"));
    }
    let outer_end = o + outer_size;
    if outer_end > sig_end {
        return Err("parseDcapQuote: outer cert-data overruns signature data".into());
    }
    need(o, SGX_REPORT_LEN, "QE report")?;
    let qe_report_body = q[o..o + SGX_REPORT_LEN].to_vec();
    o += SGX_REPORT_LEN;
    need(o, 64, "QE report signature")?;
    let qe_report_signature = q[o..o + 64].to_vec();
    o += 64;
    need(o, 2, "QE auth-data size")?;
    let auth_size = u16le(q, o);
    o += 2;
    need(o, auth_size, "QE auth-data")?;
    let qe_auth_data = q[o..o + auth_size].to_vec();
    o += auth_size;
    need(o, 6, "inner cert-data header")?;
    let inner_type = u16le(q, o);
    let inner_size = u32le(q, o + 2);
    o += 6;
    if inner_type != 5 {
        return Err(format!("parseDcapQuote: inner cert-data type {inner_type} (expected PCK-cert-chain = 5)"));
    }
    if o + inner_size > outer_end {
        return Err("parseDcapQuote: inner cert-data overruns outer cert-data".into());
    }
    let pck_chain_pem: String = q[o..o + inner_size].iter().map(|c| *c as char).collect();
    if q[sig_end..].iter().any(|x| *x != 0) {
        return Err("parseDcapQuote: non-zero bytes after the signature data".into());
    }
    Ok(DcapQuote { header, td_report_body: td, quote_signature, ak_pub_raw, qe_report_body, qe_report_signature, qe_auth_data, pck_chain_pem })
}

// ───────────────────────────── the Intel SGX extension of the PCK leaf

const OID_SGX_FMSPC: [u8; 12] = [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04];
const OID_SGX_TCB: [u8; 12] = [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02];

pub struct PckTcb {
    pub fmspc: Vec<u8>,
    pub sgx_tcb_components: [u8; 16],
    pub pcesvn: i64,
}

/// `readDerTlv` of attest-intel-tdx.ts: lengths of up to four octets; `None` on any malformed or overrunning length.
fn read_der_tlv(buf: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    if off + 2 > buf.len() {
        return None;
    }
    let tag = buf[off];
    let mut len = buf[off + 1] as usize;
    let mut p = off + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || p + n > buf.len() {
            return None;
        }
        len = 0;
        for _ in 0..n {
            len = len * 256 + buf[p] as usize;
            p += 1;
        }
    }
    let end = p + len;
    if end > buf.len() {
        return None;
    }
    Some((tag, p, end))
}

fn index_of(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|i| &hay[*i..*i + needle.len()] == needle)
}

/// `extractPckFmspcAndTcb`: FMSPC and the issued TCB from the PCK leaf's Intel SGX extension (byte scan, as the reference).
pub fn extract_pck_fmspc_and_tcb(leaf: &[u8]) -> Result<PckTcb, String> {
    let pre = "extractPckFmspcAndTcb";
    let fi = index_of(leaf, &OID_SGX_FMSPC).ok_or_else(|| format!("{pre}: FMSPC OID not found in certificate"))?;
    let fmspc = match read_der_tlv(leaf, fi + OID_SGX_FMSPC.len()) {
        Some((0x04, s, e)) if e - s == 6 => leaf[s..e].to_vec(),
        _ => return Err(format!("{pre}: malformed FMSPC OCTET STRING")),
    };
    let ti = index_of(leaf, &OID_SGX_TCB).ok_or_else(|| format!("{pre}: TCB OID not found in certificate"))?;
    let (seq_tag, seq_start, seq_end) = read_der_tlv(leaf, ti + OID_SGX_TCB.len()).ok_or_else(|| format!("{pre}: malformed TCB SEQUENCE"))?;
    if seq_tag != 0x30 {
        return Err(format!("{pre}: malformed TCB SEQUENCE"));
    }
    let mut comps = [0u8; 16];
    let mut pcesvn: i64 = -1;
    let mut p = seq_start;
    let mut idx = 0;
    while p < seq_end {
        let (ptag, pstart, pend) = read_der_tlv(leaf, p).ok_or_else(|| format!("{pre}: malformed TCB component"))?;
        if ptag != 0x30 {
            return Err(format!("{pre}: malformed TCB component"));
        }
        let (otag, _ostart, oend) = read_der_tlv(leaf, pstart).ok_or_else(|| format!("{pre}: TCB component missing OID"))?;
        if otag != 0x06 {
            return Err(format!("{pre}: TCB component missing OID"));
        }
        let (vtag, vstart, vend) = read_der_tlv(leaf, oend).ok_or_else(|| format!("{pre}: TCB component missing value"))?;
        let last = leaf[oend - 1] as usize;
        if vtag == 0x02 {
            let mut n: i64 = 0;
            for b in vstart..vend {
                n = ((n << 8) | leaf[b] as i64) & 0xffff_ffff;
            }
            if (1..=16).contains(&last) {
                comps[last - 1] = (n & 0xff) as u8;
            } else if last == 17 {
                pcesvn = n & 0xffff;
            }
        }
        p = pend;
        idx += 1;
        if idx > 64 {
            break;
        }
    }
    if pcesvn < 0 {
        return Err(format!("{pre}: PCESVN not found in TCB extension"));
    }
    Ok(PckTcb { fmspc, sgx_tcb_components: comps, pcesvn })
}

// ───────────────────────────── the PCK chain

pub struct PckChain {
    pub leaf_key: PubKey,
    pub leaf_der: Vec<u8>,
    pub leaf: Cert,
}

fn wrap_pck(e: String) -> String {
    format!("PCK chain X.509 verification error (fail closed): {e}")
}

/// `verifyIntelPckChainX509`. `Err((reason, is_validity_failure))`.
pub fn verify_intel_pck_chain(pem: &str, pin: &str, now_ms: f64) -> Result<PckChain, (String, bool)> {
    let blocks = pem_blocks(pem);
    if blocks.is_empty() {
        return Err(("no PEM certificates in the PCK chain".into(), false));
    }
    let mut certs: Vec<Cert> = Vec::new();
    for b in &blocks {
        certs.push(Cert::from_pem(b).map_err(|e| (wrap_pck(e), false))?);
    }
    let n = certs.len();
    let subjects: Vec<String> = certs.iter().map(|c| c.subject_string()).collect();
    let issuers: Vec<String> = certs.iter().map(|c| c.issuer_string()).collect();
    let leaf_idx = (0..n).find(|i| !issuers.contains(&subjects[*i])).unwrap_or(0);
    let mut ordered: Vec<usize> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    let mut cur = Some(leaf_idx);
    while let Some(ci) = cur {
        if seen.contains(&subjects[ci]) {
            break;
        }
        ordered.push(ci);
        seen.push(subjects[ci].clone());
        if subjects[ci] == issuers[ci] {
            break;
        }
        cur = (0..n).rev().find(|j| subjects[*j] == issuers[ci]);
    }
    let root_i = *ordered.last().unwrap_or(&leaf_idx);
    if subjects[root_i] != issuers[root_i] {
        return Err(("PCK chain does not terminate in a self-signed root".into(), false));
    }
    if ordered.len() != n {
        return Err(("PCK chain is not a single connected path (orphan/duplicate certificates)".into(), false));
    }
    if !now_ms.is_finite() {
        return Err(("nowMs is not a finite number".into(), false));
    }
    for ci in &ordered {
        if !x509_valid_at(&certs[*ci].raw, now_ms, 0.0) {
            return Err(("PCK chain certificate outside its validity period".into(), true));
        }
    }
    for i in 0..ordered.len() - 1 {
        let child = &certs[ordered[i]];
        let parent = &certs[ordered[i + 1]];
        if child.issuer_string() != parent.subject_string() {
            return Err((format!("certificate at depth {i} issuer does not match its parent subject"), false));
        }
        let pk = parent.public_key().map_err(|e| (wrap_pck(e), false))?;
        if !child.verify(&pk) {
            return Err((format!("certificate at depth {i} is not signed by its issuer"), false));
        }
    }
    let root = &certs[root_i];
    let root_key = root.public_key().map_err(|e| (wrap_pck(e), false))?;
    if !root.verify(&root_key) {
        return Err(("root certificate is not self-signed".into(), false));
    }
    if root_key.spki_sha256_hex() != pin.to_lowercase() {
        return Err(("Intel SGX Root CA does not match the pinned trust anchor".into(), false));
    }
    let raws: Vec<Vec<u8>> = ordered.iter().map(|i| certs[*i].raw.clone()).collect();
    if let Some(role) = check_chain_roles(&raws) {
        return Err((role, false));
    }
    for (i, raw) in raws.iter().enumerate() {
        let crit = unrecognised_critical_extension(raw, None).map_err(|e| (wrap_pck(e), false))?;
        if let Some(oid) = crit {
            return Err((format!("PCK chain certificate at depth {i} has an unrecognised critical extension {oid}"), false));
        }
    }
    let leaf = certs[ordered[0]].clone();
    let key = leaf.public_key().map_err(|e| (wrap_pck(e), false))?;
    match &key {
        PubKey::Ec { curve, .. } => {
            if *curve != EcCurve::P256 {
                return Err((wrap_pck(format!("public key is not on P-256 (got {})", key.jwk_crv())), false));
            }
        }
        other => return Err((format!("PCK leaf key is not EC (got {})", other.type_name()), false)),
    }
    if let PubKey::Ec { curve, point } = &key {
        if !ec_point_valid(*curve, point) {
            return Err((wrap_pck("Point is not on curve".into()), false));
        }
    }
    Ok(PckChain { leaf_key: key, leaf_der: leaf.raw.clone(), leaf })
}

// ───────────────────────────── the quote

#[derive(Clone, Debug, Default)]
pub struct DcapPolicy {
    pub mrtds: Vec<String>,
    pub fmspcs: Option<Vec<String>>,
    pub rtmrs: Option<Vec<String>>,
    pub mr_seams: Option<Vec<String>>,
    pub mr_signer_seams: Option<Vec<String>>,
    pub allow_debug: bool,
}

pub struct GenuineTdx {
    pub report_data: Vec<u8>,
    pub fmspc: String,
    pub mrtd_hex: String,
    pub pck: PckTcb,
}

fn p256_verify(msg: &[u8], sig: &[u8], key: &PubKey) -> bool {
    match key {
        PubKey::Ec { curve, point } if *curve == EcCurve::P256 => ecdsa_verify_raw(*curve, point, &sha256(msg), sig),
        _ => false,
    }
}

fn td(body: &[u8], off: usize, len: usize) -> &[u8] {
    &body[off..off + len]
}

/// `verifyGenuineTdxQuote` (without the optional `expected` binding, which the verifier checks itself).
pub fn verify_genuine_tdx_quote(quote: &[u8], pin: &str, now_ms: f64, policy: &DcapPolicy) -> Result<(GenuineTdx, DcapQuote), String> {
    let q = parse_dcap_quote(quote).map_err(|e| format!("quote parse failed: {e}"))?;
    let chain = verify_intel_pck_chain(&q.pck_chain_pem, pin, now_ms).map_err(|(r, _)| format!("PCK chain invalid: {r}"))?;
    let pck = extract_pck_fmspc_and_tcb(&chain.leaf_der).map_err(|e| format!("PCK FMSPC/TCB extraction failed: {e}"))?;
    if !p256_verify(&q.qe_report_body, &q.qe_report_signature, &chain.leaf_key) {
        return Err("QE report signature does not verify under the PCK leaf".into());
    }
    if q.qe_report_body[QE_ATTRIBUTES_OFF] & 0x02 != 0 {
        return Err("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)".into());
    }
    let qe_rd = &q.qe_report_body[QE_REPORT_DATA_OFF..QE_REPORT_DATA_OFF + 64];
    let mut ak_in = q.ak_pub_raw.clone();
    ak_in.extend_from_slice(&q.qe_auth_data);
    let ak_binding = sha256(&ak_in);
    if !timing_safe_eq(&qe_rd[..32], &ak_binding) || !qe_rd[32..].iter().all(|b| *b == 0) {
        return Err("QE report_data does not bind the attestation key (AK not endorsed by this QE)".into());
    }
    let mut ak_point = vec![0x04];
    ak_point.extend_from_slice(&q.ak_pub_raw);
    if !ec_point_valid(EcCurve::P256, &ak_point) {
        return Err("attestation public key is not a valid P-256 point".into());
    }
    let ak = PubKey::Ec { curve: EcCurve::P256, point: ak_point };
    let mut signed = q.header.clone();
    signed.extend_from_slice(&q.td_report_body);
    if !p256_verify(&signed, &q.quote_signature, &ak) {
        return Err("TD quote signature does not verify under the attestation key".into());
    }
    let body = &q.td_report_body;
    let td_attributes0 = td(body, 120, 8)[0];
    if !policy.allow_debug && td_attributes0 & 1 != 0 {
        return Err("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)".into());
    }
    let fmspc_hex = hex_lower(&pck.fmspc);
    let mrtd_hex = hex_lower(td(body, 136, 48));
    if !policy.mrtds.is_empty() && !policy.mrtds.contains(&mrtd_hex) {
        return Err("MRTD not in policy allowlist".into());
    }
    if let Some(f) = &policy.fmspcs {
        if !f.is_empty() && !f.contains(&fmspc_hex) {
            return Err("FMSPC not in policy allowlist".into());
        }
    }
    if let Some(m) = &policy.mr_seams {
        if !m.contains(&hex_lower(td(body, 16, 48))) {
            return Err("MRSEAM not in policy allowlist".into());
        }
    }
    if let Some(m) = &policy.mr_signer_seams {
        if !m.contains(&hex_lower(td(body, 64, 48))) {
            return Err("MRSIGNERSEAM not in policy allowlist".into());
        }
    }
    if let Some(r) = &policy.rtmrs {
        if !r.is_empty() && !r.contains(&hex_lower(td(body, 328, 48))) {
            return Err("RTMR0 not in policy allowlist".into());
        }
    }
    let report_data = td(body, 520, 64).to_vec();
    Ok((GenuineTdx { report_data, fmspc: fmspc_hex, mrtd_hex, pck }, q))
}

// ───────────────────────────── CRLs

struct Crl {
    tbs: Vec<u8>,
    this_update: i64,
    next_update: i64,
    revoked: Vec<String>,
    sig: Vec<u8>,
}

#[derive(Clone, Copy)]
struct T {
    tag: u8,
    start: usize,
    end: usize,
}

fn tlv(b: &[u8], off: usize, limit: usize) -> Result<T, String> {
    if off + 2 > limit {
        return Err("DER truncated".into());
    }
    let tag = b[off];
    let mut len = b[off + 1] as usize;
    let mut p = off + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || p + n > limit {
            return Err("DER bad length".into());
        }
        len = 0;
        for i in 0..n {
            len = len * 256 + b[p + i] as usize;
        }
        p += n;
    }
    if p + len > limit {
        return Err("DER overrun".into());
    }
    Ok(T { tag, start: p, end: p + len })
}

/// `Date.UTC` with its roll-over of out-of-range fields.
fn date_utc(y: i64, mon0: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    let yy = y + mon0.div_euclid(12);
    let mm = mon0.rem_euclid(12) + 1;
    let days = super::util::days_from_civil(yy, mm, 1) + (d - 1);
    ((days * 24 + h) * 60 + mi) * 60_000 + s * 1000
}

fn digits(s: &[u8]) -> Option<Vec<i64>> {
    if s.iter().all(|c| c.is_ascii_digit()) {
        Some(s.chunks(1).map(|c| (c[0] - b'0') as i64).collect())
    } else {
        None
    }
}

fn num(s: &[u8]) -> i64 {
    digits(s).map_or(0, |d| d.iter().fold(0, |a, x| a * 10 + x))
}

fn der_time(b: &[u8], t: &T) -> Result<i64, String> {
    let s = &b[t.start..t.end];
    if t.tag == 0x17 {
        if s.len() != 13 || s[12] != b'Z' || digits(&s[..12]).is_none() {
            return Err("bad UTCTime".into());
        }
        let yy = num(&s[0..2]);
        return Ok(date_utc(if yy >= 50 { 1900 + yy } else { 2000 + yy }, num(&s[2..4]) - 1, num(&s[4..6]), num(&s[6..8]), num(&s[8..10]), num(&s[10..12])));
    }
    if t.tag == 0x18 {
        if s.len() != 15 || s[14] != b'Z' || digits(&s[..14]).is_none() {
            return Err("bad GeneralizedTime".into());
        }
        return Ok(date_utc(num(&s[0..4]), num(&s[4..6]) - 1, num(&s[6..8]), num(&s[8..10]), num(&s[10..12]), num(&s[12..14])));
    }
    Err("not a DER time".into())
}

fn norm_serial(hex: &str) -> String {
    hex.to_lowercase().trim_start_matches('0').to_string()
}

fn parse_crl(der: &[u8]) -> Result<Crl, String> {
    let outer = tlv(der, 0, der.len())?;
    if outer.tag != 0x30 || outer.end != der.len() {
        return Err("CRL: bad outer SEQUENCE".into());
    }
    let tbs_t = tlv(der, outer.start, outer.end)?;
    if tbs_t.tag != 0x30 {
        return Err("CRL: bad TBSCertList".into());
    }
    let tbs = der[outer.start..tbs_t.end].to_vec();
    let alg_t = tlv(der, tbs_t.end, outer.end)?;
    let sig_t = tlv(der, alg_t.end, outer.end)?;
    if sig_t.tag != 0x03 || sig_t.end != outer.end {
        return Err("CRL: bad signature".into());
    }
    let sig = der[(sig_t.start + 1).min(sig_t.end)..sig_t.end].to_vec();
    let mut p = tbs_t.start;
    let mut t = tlv(der, p, tbs_t.end)?;
    if t.tag == 0x02 {
        p = t.end;
        t = tlv(der, p, tbs_t.end)?;
    }
    p = t.end;
    let _ = p;
    let iss = tlv(der, t.end, tbs_t.end)?;
    if iss.tag != 0x30 {
        return Err("CRL: bad issuer".into());
    }
    let tu = tlv(der, iss.end, tbs_t.end)?;
    let this_update = der_time(der, &tu)?;
    let mut q = tu.end;
    let mut next_update: Option<i64> = None;
    let mut revoked: Vec<String> = Vec::new();
    if q < tbs_t.end {
        let mut n = tlv(der, q, tbs_t.end)?;
        if n.tag == 0x17 || n.tag == 0x18 {
            next_update = Some(der_time(der, &n)?);
            q = n.end;
        }
        if q < tbs_t.end {
            n = tlv(der, q, tbs_t.end)?;
            if n.tag == 0x30 {
                let mut e = n.start;
                while e < n.end {
                    let ent = tlv(der, e, n.end)?;
                    let ser = tlv(der, ent.start, ent.end)?;
                    if ser.tag != 0x02 {
                        return Err("CRL: bad revoked entry".into());
                    }
                    revoked.push(norm_serial(&hex_lower(&der[ser.start..ser.end])));
                    e = ent.end;
                }
            }
        }
    }
    let next_update = next_update.ok_or_else(|| "CRL: missing nextUpdate".to_string())?;
    Ok(Crl { tbs, this_update, next_update, revoked, sig })
}

/// `verifyCrl`: the revoked serials (lowercase hex, no leading zeros) of a CRL signed by `issuer_key` and fresh at `now_ms`.
pub fn verify_crl(crl_der: &[u8], issuer_key: &PubKey, now_ms: f64) -> Result<Vec<String>, String> {
    let crl = parse_crl(crl_der).map_err(|e| format!("CRL parse failed: {e}"))?;
    if !verify_der_sig(issuer_key, Hash::Sha256, &crl.tbs, &crl.sig) {
        return Err("CRL signature does not verify under the issuer".into());
    }
    if now_ms < crl.this_update as f64 {
        return Err("CRL thisUpdate is in the future".into());
    }
    if now_ms > crl.next_update as f64 {
        return Err("CRL is stale (nextUpdate passed)".into());
    }
    Ok(crl.revoked)
}

pub fn serial_is_revoked(revoked: &[String], serial_hex: &str) -> bool {
    let s = norm_serial(serial_hex);
    revoked.iter().any(|r| *r == s)
}

// ───────────────────────────── collateral

const STATUS_ORDER: [&str; 7] = ["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked"];

fn as_status(v: Option<&Value>) -> Option<&'static str> {
    let s = v?.as_str()?;
    STATUS_ORDER.iter().find(|x| **x == s).copied()
}

fn rank(s: &str) -> usize {
    STATUS_ORDER.iter().position(|x| *x == s).unwrap_or(0)
}

fn worst<'a>(a: &'a str, b: &'a str) -> &'a str {
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

fn is_rec(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

fn svns(v: Option<&Value>) -> Option<Vec<f64>> {
    let a = v?.as_array()?;
    if a.len() != 16 {
        return None;
    }
    let mut out = Vec::new();
    for c in a {
        out.push(c.as_object()?.get("svn")?.as_f64()?);
    }
    Some(out)
}

fn hex_bytes(v: Option<&Value>, len: usize) -> Option<Vec<u8>> {
    let s = v?.as_str()?;
    if s.len() != len * 2 || !is_hex(s) {
        return None;
    }
    hex_decode(s)
}

fn advisories(level: &Map<String, Value>) -> Vec<String> {
    match level.get("advisoryIDs").and_then(Value::as_array) {
        Some(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        None => Vec::new(),
    }
}

fn masked_eq(value: &[u8], mask: &[u8], expected: &[u8]) -> bool {
    for i in 0..value.len() {
        if ((value[i] & mask[i]) ^ (expected[i] & mask[i])) != 0 {
            return false;
        }
    }
    true
}

struct TcbEval {
    platform: &'static str,
    module: &'static str,
    advisories: Vec<String>,
}

fn evaluate_tcb(info: &Map<String, Value>, pck: &PckTcb, tee_tcb_svn: &[u8], mr_signer_seam: &[u8], seam_attributes: &[u8]) -> Result<TcbEval, String> {
    let levels = match info.get("tcbLevels").and_then(Value::as_array) {
        Some(l) if !l.is_empty() => l,
        _ => return Err("TCB info has no tcbLevels".into()),
    };
    let minor = tee_tcb_svn[1];
    let mut module_status: &'static str = "UpToDate";
    let mut adv: Vec<String> = Vec::new();
    let mod_mr_signer: Option<&Value>;
    let mod_attr: Option<&Value>;
    let mod_mask: Option<&Value>;
    if minor > 0 {
        let id = format!("TDX_{:02X}", minor);
        let ident = info.get("tdxModuleIdentities").and_then(Value::as_array).and_then(|ids| ids.iter().filter_map(Value::as_object).find(|x| x.get("id").and_then(Value::as_str) == Some(id.as_str())));
        let ident = match ident {
            Some(i) => i,
            None => return Err(format!("TDX module identity {id} not present in TCB info")),
        };
        mod_mr_signer = ident.get("mrsigner");
        mod_attr = ident.get("attributes");
        mod_mask = ident.get("attributesMask");
        let empty: Vec<Value> = Vec::new();
        let lv = ident.get("tcbLevels").and_then(Value::as_array).unwrap_or(&empty);
        let hit = lv.iter().filter_map(Value::as_object).find(|l| l.get("tcb").and_then(Value::as_object).and_then(|t| t.get("isvsvn")).and_then(Value::as_f64).map_or(false, |v| v <= tee_tcb_svn[0] as f64));
        let hit = match hit {
            Some(h) => h,
            None => return Err(format!("TDX module {id} SVN {} is below every known level", tee_tcb_svn[0])),
        };
        module_status = match as_status(hit.get("tcbStatus")) {
            Some(s) => s,
            None => return Err("TDX module level has an unknown tcbStatus".into()),
        };
        for a in advisories(hit) {
            if !adv.contains(&a) {
                adv.push(a);
            }
        }
    } else {
        let m = match info.get("tdxModule").and_then(Value::as_object) {
            Some(m) => m,
            None => return Err("TCB info missing tdxModule".into()),
        };
        mod_mr_signer = m.get("mrsigner");
        mod_attr = m.get("attributes");
        mod_mask = m.get("attributesMask");
    }
    let (ex_mr, ex_attr, mask) = match (hex_bytes(mod_mr_signer, 48), hex_bytes(mod_attr, 8), hex_bytes(mod_mask, 8)) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err("TDX module identity fields malformed".into()),
    };
    if ex_mr != mr_signer_seam {
        return Err("TD report MRSIGNERSEAM does not match the TDX module identity".into());
    }
    if !masked_eq(seam_attributes, &mask, &ex_attr) {
        return Err("TD report SEAM attributes do not match the TDX module identity".into());
    }
    let from = if minor > 0 { 2 } else { 0 };
    for l in levels {
        let lo = match l.as_object() {
            Some(o) => o,
            None => return Err("malformed TCB level".into()),
        };
        let tcb = match lo.get("tcb").and_then(Value::as_object) {
            Some(t) => t,
            None => return Err("malformed TCB level".into()),
        };
        let (sgx, tdx, pce) = match (svns(tcb.get("sgxtcbcomponents")), svns(tcb.get("tdxtcbcomponents")), tcb.get("pcesvn").and_then(Value::as_f64)) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return Err("malformed TCB level components".into()),
        };
        let st = match as_status(lo.get("tcbStatus")) {
            Some(s) => s,
            None => return Err("TCB level has an unknown tcbStatus".into()),
        };
        let mut matched = pck.pcesvn as f64 >= pce;
        for i in 0..16 {
            if !matched {
                break;
            }
            if (pck.sgx_tcb_components[i] as f64) < sgx[i] {
                matched = false;
            }
        }
        for i in from..16 {
            if !matched {
                break;
            }
            if (tee_tcb_svn[i] as f64) < tdx[i] {
                matched = false;
            }
        }
        if !matched {
            continue;
        }
        for a in advisories(lo) {
            if !adv.contains(&a) {
                adv.push(a);
            }
        }
        adv.sort();
        return Ok(TcbEval { platform: st, module: module_status, advisories: adv });
    }
    Err("platform TCB is below every level in the TCB info".into())
}

struct QeEval {
    status: &'static str,
    advisories: Vec<String>,
}

fn evaluate_qe(ident: &Map<String, Value>, qe: &[u8]) -> Result<QeEval, String> {
    if ident.get("id").and_then(Value::as_str) != Some("TD_QE") {
        return Err("QE identity id is not TD_QE".into());
    }
    if ident.get("version").and_then(Value::as_f64) != Some(2.0) {
        return Err("unsupported QE identity version".into());
    }
    let miscsel = hex_bytes(ident.get("miscselect"), 4);
    let misc_mask = hex_bytes(ident.get("miscselectMask"), 4);
    let attr = hex_bytes(ident.get("attributes"), 16);
    let attr_mask = hex_bytes(ident.get("attributesMask"), 16);
    let mrsigner = hex_bytes(ident.get("mrsigner"), 32);
    let prodid = ident.get("isvprodid").and_then(Value::as_f64);
    let (miscsel, misc_mask, attr, attr_mask, mrsigner, prodid) = match (miscsel, misc_mask, attr, attr_mask, mrsigner, prodid) {
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) => (a, b, c, d, e, f),
        _ => return Err("QE identity fields malformed".into()),
    };
    if qe.len() != 384 {
        return Err("QE report has wrong length".into());
    }
    if !masked_eq(&qe[16..20], &misc_mask, &miscsel) {
        return Err("QE MISCSELECT does not match the QE identity".into());
    }
    if !masked_eq(&qe[48..64], &attr_mask, &attr) {
        return Err("QE ATTRIBUTES do not match the QE identity".into());
    }
    if qe[128..160] != mrsigner[..] {
        return Err("QE MRSIGNER does not match the QE identity".into());
    }
    let prod = qe[256] as u32 | (qe[257] as u32) << 8;
    let isvsvn = qe[258] as u32 | (qe[259] as u32) << 8;
    if prod as f64 != prodid {
        return Err("QE ISVPRODID does not match the QE identity".into());
    }
    let empty: Vec<Value> = Vec::new();
    let lv = ident.get("tcbLevels").and_then(Value::as_array).unwrap_or(&empty);
    let hit = lv.iter().filter_map(Value::as_object).find(|l| l.get("tcb").and_then(Value::as_object).and_then(|t| t.get("isvsvn")).and_then(Value::as_f64).map_or(false, |v| v <= isvsvn as f64));
    let hit = match hit {
        Some(h) => h,
        None => return Err("QE ISVSVN is below every known level".into()),
    };
    let st = match as_status(hit.get("tcbStatus")) {
        Some(s) => s,
        None => return Err("QE level has an unknown tcbStatus".into()),
    };
    Ok(QeEval { status: st, advisories: advisories(hit) })
}

/// The exact source text of the JSON object following `"<name>":` at the start of `text` (string-aware brace matching).
fn raw_json_object(text: &str, name: &str) -> Option<String> {
    let cs: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    let skip = |i: &mut usize| {
        while *i < cs.len() && cs[*i].is_whitespace() {
            *i += 1;
        }
    };
    skip(&mut i);
    if cs.get(i) != Some(&'{') {
        return None;
    }
    i += 1;
    skip(&mut i);
    let want: Vec<char> = format!("\"{name}\"").chars().collect();
    if cs.len() < i + want.len() || cs[i..i + want.len()] != want[..] {
        return None;
    }
    i += want.len();
    skip(&mut i);
    if cs.get(i) != Some(&':') {
        return None;
    }
    i += 1;
    skip(&mut i);
    if cs.get(i) != Some(&'{') {
        return None;
    }
    let s = i;
    let mut depth = 0i64;
    let mut in_str = false;
    while i < cs.len() {
        let ch = cs[i];
        if in_str {
            if ch == '\\' {
                i += 1;
            } else if ch == '"' {
                in_str = false;
            }
        } else if ch == '"' {
            in_str = true;
        } else if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(cs[s..=i].iter().collect());
            }
        }
        i += 1;
    }
    None
}

fn verify_signed_json(text: &str, name: &str, key: &PubKey) -> Result<Map<String, Value>, String> {
    let raw = raw_json_object(text, name).ok_or_else(|| format!("{name} not found / malformed"))?;
    let doc: Value = serde_json::from_str(text).map_err(|_| format!("{name} document is not valid JSON"))?;
    let sig = match doc.get("signature").and_then(Value::as_str) {
        Some(s) if s.len() == 128 && is_hex(s) => s.to_string(),
        _ => return Err(format!("{name} signature missing or malformed")),
    };
    let sig_bytes = hex_decode(&sig).unwrap_or_default();
    if !verify_p1363_sig(key, Hash::Sha256, raw.as_bytes(), &sig_bytes) {
        return Err(format!("{name} signature does not verify under the TCB Signing certificate"));
    }
    match doc.get(name) {
        Some(Value::Object(o)) => Ok(o.clone()),
        _ => Err(format!("{name} is not an object")),
    }
}

fn check_fresh(body: &Map<String, Value>, what: &str, now_ms: f64) -> Option<String> {
    let issue = body.get("issueDate").and_then(Value::as_str).and_then(parse_iso_ms);
    let next = body.get("nextUpdate").and_then(Value::as_str).and_then(parse_iso_ms);
    let (issue, next) = match (issue, next) {
        (Some(a), Some(b)) => (a as f64, b as f64),
        _ => return Some(format!("{what}: issueDate/nextUpdate missing")),
    };
    if now_ms < issue {
        return Some(format!("{what}: issueDate is in the future"));
    }
    if now_ms > next {
        return Some(format!("{what}: stale (nextUpdate passed)"));
    }
    None
}

fn signer_key_from_chain(chain_pem: &str, pin: &str, now_ms: f64, root_revoked: &[String]) -> Result<PubKey, String> {
    let chain = match verify_intel_pck_chain(chain_pem, pin, now_ms) {
        Ok(c) => c,
        Err((_, true)) => return Err("issuer chain certificate outside its validity period".into()),
        Err((r, false)) => return Err(format!("issuer chain invalid: {r}")),
    };
    for b in pem_blocks(chain_pem) {
        let c = Cert::from_pem(b)?;
        if !x509_valid_at(&c.raw, now_ms, 0.0) {
            return Err("issuer chain certificate outside its validity period".into());
        }
        if serial_is_revoked(root_revoked, &c.serial_hex()) {
            return Err("issuer chain certificate is revoked by the Intel Root CA CRL".into());
        }
    }
    Ok(chain.leaf_key)
}

pub struct Collateral {
    pub tcb_info_json: String,
    pub tcb_info_issuer_chain_pem: String,
    pub qe_identity_json: String,
    pub qe_identity_issuer_chain_pem: String,
    pub pck_crl_der: Vec<u8>,
    pub root_crl_der: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct CollateralPolicy {
    pub accept_statuses: Option<Vec<String>>,
    pub min_tcb_evaluation_data_number: Option<f64>,
}

#[derive(Default)]
pub struct CollateralResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub status: Option<String>,
    pub advisory_ids: Vec<String>,
}

fn cfail(r: impl Into<String>) -> CollateralResult {
    CollateralResult { ok: false, reason: Some(r.into()), ..Default::default() }
}

/// `verifyIntelTdxCollateral`: signed TCB info + QE identity + CRLs, evaluated against the quote.
pub fn verify_intel_tdx_collateral(quote: &[u8], c: &Collateral, now_ms: f64, policy: &CollateralPolicy, pin: &str, allow_debug: bool) -> CollateralResult {
    match collateral_inner(quote, c, now_ms, policy, pin, allow_debug) {
        Ok(r) => r,
        Err(e) => cfail(format!("collateral verification error (fail closed): {e}")),
    }
}

fn collateral_inner(quote: &[u8], c: &Collateral, now_ms: f64, policy: &CollateralPolicy, pin: &str, allow_debug: bool) -> Result<CollateralResult, String> {
    if c.tcb_info_json.is_empty() || c.qe_identity_json.is_empty() || c.pck_crl_der.is_empty() || c.root_crl_der.is_empty() || c.tcb_info_issuer_chain_pem.is_empty() || c.qe_identity_issuer_chain_pem.is_empty() {
        return Ok(cfail("collateral incomplete (fail closed)"));
    }
    let pol = DcapPolicy { allow_debug, ..Default::default() };
    let base = match verify_genuine_tdx_quote(quote, pin, now_ms, &pol) {
        Ok(b) => b,
        Err(r) => return Ok(cfail(format!("quote invalid: {r}"))),
    };
    let (base, q) = base;
    let quote_certs: Vec<Cert> = pem_blocks(&q.pck_chain_pem).iter().map(|b| Cert::from_pem(b)).collect::<Result<Vec<_>, _>>()?;
    for x in &quote_certs {
        if !x509_valid_at(&x.raw, now_ms, 0.0) {
            return Ok(cfail("PCK chain certificate outside its validity period"));
        }
    }
    let leaf = match quote_certs.iter().find(|x| !quote_certs.iter().any(|y| y.issuer_string() == x.subject_string())) {
        Some(l) => l,
        None => return Ok(cfail("PCK leaf not found")),
    };
    let ca = match quote_certs.iter().find(|x| x.subject_string() == leaf.issuer_string()) {
        Some(x) => x,
        None => return Ok(cfail("PCK CA not found in the quote chain")),
    };
    let root = match quote_certs.iter().find(|x| x.subject_string() == x.issuer_string()) {
        Some(x) => x,
        None => return Ok(cfail("Intel root not found in the quote chain")),
    };
    let root_revoked = match verify_crl(&c.root_crl_der, &root.public_key()?, now_ms) {
        Ok(r) => r,
        Err(e) => return Ok(cfail(format!("Intel Root CA CRL: {e}"))),
    };
    let pck_revoked = match verify_crl(&c.pck_crl_der, &ca.public_key()?, now_ms) {
        Ok(r) => r,
        Err(e) => return Ok(cfail(format!("PCK CRL: {e}"))),
    };
    if serial_is_revoked(&root_revoked, &ca.serial_hex()) {
        return Ok(cfail("PCK CA certificate is revoked by the Intel Root CA CRL"));
    }
    if serial_is_revoked(&pck_revoked, &leaf.serial_hex()) {
        return Ok(cfail("PCK leaf certificate is revoked by the PCK CRL"));
    }

    let tcb_key = match signer_key_from_chain(&c.tcb_info_issuer_chain_pem, pin, now_ms, &root_revoked) {
        Ok(k) => k,
        Err(e) => return Ok(cfail(format!("TCB info: {e}"))),
    };
    let info = match verify_signed_json(&c.tcb_info_json, "tcbInfo", &tcb_key) {
        Ok(b) => b,
        Err(e) => return Ok(cfail(format!("TCB info: {e}"))),
    };
    if let Some(stale) = check_fresh(&info, "TCB info", now_ms) {
        return Ok(cfail(stale));
    }
    if info.get("id").and_then(Value::as_str) != Some("TDX") || info.get("version").and_then(Value::as_f64) != Some(3.0) {
        return Ok(cfail("TCB info is not a TDX v3 document"));
    }
    match info.get("fmspc").and_then(Value::as_str) {
        Some(f) if f.to_lowercase() == base.fmspc => {}
        _ => return Ok(cfail("TCB info FMSPC does not match the quote PCK")),
    }

    let qe_key = match signer_key_from_chain(&c.qe_identity_issuer_chain_pem, pin, now_ms, &root_revoked) {
        Ok(k) => k,
        Err(e) => return Ok(cfail(format!("QE identity: {e}"))),
    };
    let qe_doc = match verify_signed_json(&c.qe_identity_json, "enclaveIdentity", &qe_key) {
        Ok(b) => b,
        Err(e) => return Ok(cfail(format!("QE identity: {e}"))),
    };
    if let Some(stale) = check_fresh(&qe_doc, "QE identity", now_ms) {
        return Ok(cfail(stale));
    }
    let info_num = info.get("tcbEvaluationDataNumber").and_then(Value::as_f64).unwrap_or(-1.0);
    let qe_num = qe_doc.get("tcbEvaluationDataNumber").and_then(Value::as_f64).unwrap_or(-1.0);
    if info_num < 0.0 || qe_num < 0.0 {
        return Ok(cfail("tcbEvaluationDataNumber missing"));
    }
    if let Some(min) = policy.min_tcb_evaluation_data_number {
        if info_num < min || qe_num < min {
            return Ok(cfail("tcbEvaluationDataNumber below policy minimum"));
        }
    }

    let body = &q.td_report_body;
    let pck = extract_pck_fmspc_and_tcb(&leaf.raw)?;
    let tcb = match evaluate_tcb(&info, &pck, &body[0..16], &body[64..112], &body[112..120]) {
        Ok(t) => t,
        Err(e) => return Ok(cfail(format!("TCB evaluation: {e}"))),
    };
    let qe = match evaluate_qe(&qe_doc, &q.qe_report_body) {
        Ok(t) => t,
        Err(e) => return Ok(cfail(format!("QE identity: {e}"))),
    };
    let status = worst(worst(tcb.platform, tcb.module), qe.status);
    let mut ids: Vec<String> = Vec::new();
    for a in tcb.advisories.iter().chain(qe.advisories.iter()) {
        if !ids.contains(a) {
            ids.push(a.clone());
        }
    }
    ids.sort();
    let default_accept: Vec<String> = vec!["UpToDate".into(), "SWHardeningNeeded".into()];
    let accepted = policy.accept_statuses.as_ref().unwrap_or(&default_accept);
    let mut res = CollateralResult { ok: false, reason: None, status: Some(status.to_string()), advisory_ids: ids };
    if !accepted.iter().any(|a| a == status) {
        res.reason = Some(format!("TCB status {status} is not accepted by policy"));
        return Ok(res);
    }
    res.ok = true;
    Ok(res)
}

// ───────────────────────────── the verifier

pub struct DcapVerifier {
    pin: String,
    report_data_mode: bool,
    policy: DcapPolicy,
    collateral_policy: Option<CollateralPolicy>,
    allow_missing_collateral: bool,
}

fn hex96_list(cfg: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, String> {
    let v = match cfg.get(key) {
        None => return Ok(None),
        Some(v) => v,
    };
    let bad_list = || format!("createIntelDcapVerifier: policy.{key}, if given, must be a NON-EMPTY list");
    let arr = v.as_array().ok_or_else(bad_list)?;
    if arr.is_empty() {
        return Err(bad_list());
    }
    let mut out = Vec::new();
    for x in arr {
        match x.as_str() {
            Some(s) if is_hex(s) && s.len() == 96 => out.push(s.to_string()),
            _ => return Err(format!("createIntelDcapVerifier: every {key} entry must be 96 hex chars (48 bytes)")),
        }
    }
    Ok(Some(lower_list(&out)))
}

impl DcapVerifier {
    pub fn from_config(cfg: &Map<String, Value>) -> Result<DcapVerifier, String> {
        let binding = cfg.get("binding").and_then(Value::as_str);
        if binding != Some("report-data") && binding != Some("azure-runtime-data") {
            return Err("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'".into());
        }
        let empty = Map::new();
        let pol = cfg.get("policy").and_then(Value::as_object).unwrap_or(&empty);
        let mrtds_raw = pol.get("mrtds").and_then(str_array);
        let mrtds = match mrtds_raw {
            Some(m) if !m.is_empty() => lower_list(&m),
            _ => return Err("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)".into()),
        };
        if mrtds.iter().any(|m| !is_hex(m) || m.len() != 96) {
            return Err("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)".into());
        }
        let mr_seams = hex96_list(pol, "mrSeams")?;
        let mr_signer_seams = hex96_list(pol, "mrSignerSeams")?;
        let pin = cfg.get("trustAnchorRootCaSpkiSha256").and_then(Value::as_str).unwrap_or(INTEL_SGX_ROOT_CA_SPKI_SHA256).to_lowercase();
        let list = |k: &str| -> Option<Vec<String>> { pol.get(k).and_then(str_array).map(|v| lower_list(&v)) };
        let collateral_policy = pol.get("collateral").and_then(Value::as_object).map(|c| CollateralPolicy {
            accept_statuses: c.get("acceptStatuses").and_then(str_array),
            min_tcb_evaluation_data_number: c.get("minTcbEvaluationDataNumber").and_then(Value::as_f64),
        });
        Ok(DcapVerifier {
            pin,
            report_data_mode: binding == Some("report-data"),
            policy: DcapPolicy { mrtds, fmspcs: list("fmspcs"), rtmrs: list("rtmrs"), mr_seams, mr_signer_seams, allow_debug: pol.get("allowDebug").and_then(Value::as_bool) == Some(true) },
            collateral_policy,
            allow_missing_collateral: cfg.get("allowMissingCollateral").and_then(Value::as_bool) == Some(true),
        })
    }

    pub fn verify(&self, ev: Option<&Value>, now_ms: i64, expected: Option<&Binding>) -> AttResult {
        let obj = match ev.and_then(Value::as_object) {
            Some(o) => o,
            None => return AttResult::fail("no Intel DCAP quote for this action"),
        };
        let quote = match obj.get("quote").and_then(Value::as_str) {
            Some(s) => b64_lenient(s),
            None => return AttResult::fail("no Intel DCAP quote for this action"),
        };
        let expected = match expected {
            Some(e) => e,
            None => return AttResult::fail("no expected attestation binding supplied"),
        };
        let now = now_ms as f64;
        let (g, _q) = match verify_genuine_tdx_quote(&quote, &self.pin, now, &self.policy) {
            Ok(x) => x,
            Err(r) => return AttResult::fail(format!("DCAP quote invalid: {r}")),
        };
        if self.report_data_mode {
            let want = match attestation_binding(expected) {
                Ok(w) => w,
                Err(e) => return AttResult::fail(format!("binding not constructible: {e}")),
            };
            if g.report_data != want {
                return AttResult::fail("report_data does not bind holder/grant/epoch/nonce");
            }
        } else {
            let rt = match obj.get("runtimeData").and_then(Value::as_str) {
                Some(s) => b64_lenient(s),
                None => return AttResult::fail("azure-runtime-data binding needs the runtime-data JSON bytes"),
            };
            if let Some(why) = check_azure_runtime_data_binding(&g.report_data, &rt, expected) {
                return AttResult::fail(why);
            }
        }
        let mut host: Vec<(&str, String)> = vec![("attestation_type", "tdx-dcap".to_string()), ("fmspc", g.fmspc.clone())];
        match obj.get("collateral").and_then(Value::as_object) {
            Some(co) => {
                let sget = |k: &str| co.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let bget = |k: &str| co.get(k).and_then(Value::as_str).map(b64_lenient).unwrap_or_default();
                let coll = Collateral {
                    tcb_info_json: sget("tcbInfoJson"),
                    tcb_info_issuer_chain_pem: sget("tcbInfoIssuerChainPem"),
                    qe_identity_json: sget("qeIdentityJson"),
                    qe_identity_issuer_chain_pem: sget("qeIdentityIssuerChainPem"),
                    pck_crl_der: bget("pckCrlDer"),
                    root_crl_der: bget("rootCrlDer"),
                };
                let cp = self.collateral_policy.clone().unwrap_or_default();
                let c = verify_intel_tdx_collateral(&quote, &coll, now, &cp, &self.pin, self.policy.allow_debug);
                if let Some(s) = &c.status {
                    host.push(("tcb_status", s.clone()));
                }
                if !c.advisory_ids.is_empty() {
                    host.push(("advisory_ids", c.advisory_ids.join(",")));
                }
                if !c.ok {
                    return AttResult::fail(format!("Intel collateral: {}", c.reason.unwrap_or_else(|| "rejected".to_string())));
                }
            }
            None => {
                if self.allow_missing_collateral {
                    host.push(("tcb_status", "unevaluated".to_string()));
                } else {
                    return AttResult::fail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)");
                }
            }
        }
        AttResult::pass(super::default_measured(&g.mrtd_hex, ""), host)
    }
}
