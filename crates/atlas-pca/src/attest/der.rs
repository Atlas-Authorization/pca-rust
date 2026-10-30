//! Strict DER / X.509 readers shared by the chain verifiers: the CA-role rules, the strict extension table and the
//! certificate validity window. Error texts are the exact messages of the TypeScript reader (they are part of the
//! conformance vectors).

use super::util::{civil_ms, hex_lower};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug)]
pub struct Tlv {
    pub tag: u8,
    /// First content byte.
    pub start: usize,
    /// One past the last content byte.
    pub end: usize,
}

/// `readTlv` of x509-strict.ts: multi-byte tags refused, lengths minimal and at most three length octets.
pub fn read_tlv(b: &[u8], off: usize, limit: usize) -> Result<Tlv, String> {
    let limit = limit.min(b.len());
    if off + 2 > limit {
        return Err("DER: truncated header".into());
    }
    let tag = b[off];
    if tag & 0x1f == 0x1f {
        return Err("DER: multi-byte tags are not supported".into());
    }
    let mut len = b[off + 1] as usize;
    let mut p = off + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 3 {
            return Err("DER: unsupported length form".into());
        }
        if p + n > limit {
            return Err("DER: truncated length".into());
        }
        len = 0;
        if n > 1 && b[p] == 0 {
            return Err("DER: non-minimal length (leading zero)".into());
        }
        for i in 0..n {
            len = (len << 8) | b[p + i] as usize;
        }
        if len < 0x80 {
            return Err("DER: non-minimal length (long form below 128)".into());
        }
        p += n;
    }
    if p + len > limit {
        return Err("DER: element overruns its parent".into());
    }
    Ok(Tlv { tag, start: p, end: p + len })
}

#[derive(Clone, Debug, Default)]
pub struct CertRoleInfo {
    pub has_basic_constraints: bool,
    pub ca: bool,
    pub path_len: Option<i64>,
    pub has_key_usage: bool,
    pub key_cert_sign: bool,
}

const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];

fn oid_equals(b: &[u8], t: &Tlv, want: &[u8]) -> bool {
    t.tag == 0x06 && t.end - t.start == want.len() && &b[t.start..t.end] == want
}

/// `readCertRoleInfo`: the CA-role-relevant extensions of a DER certificate.
pub fn read_cert_role_info(der: &[u8]) -> Result<CertRoleInfo, String> {
    let outer = read_tlv(der, 0, der.len())?;
    if outer.tag != 0x30 {
        return Err("certificate is not a DER SEQUENCE".into());
    }
    if outer.end != der.len() {
        return Err("trailing bytes after the certificate".into());
    }
    let tbs = read_tlv(der, outer.start, outer.end)?;
    if tbs.tag != 0x30 {
        return Err("certificate has no tbsCertificate".into());
    }
    let mut info = CertRoleInfo::default();
    let mut p = tbs.start;
    while p < tbs.end {
        let el = read_tlv(der, p, tbs.end)?;
        p = el.end;
        if el.tag != 0xa3 {
            continue;
        }
        let seq = read_tlv(der, el.start, el.end)?;
        if seq.tag != 0x30 {
            return Err("extensions is not a SEQUENCE".into());
        }
        let mut q = seq.start;
        while q < seq.end {
            let ext = read_tlv(der, q, seq.end)?;
            q = ext.end;
            if ext.tag != 0x30 {
                return Err("extension is not a SEQUENCE".into());
            }
            let id = read_tlv(der, ext.start, ext.end)?;
            let mut r = id.end;
            let mut next = read_tlv(der, r, ext.end)?;
            if next.tag == 0x01 {
                r = next.end;
                next = read_tlv(der, r, ext.end)?;
            }
            if next.tag != 0x04 {
                return Err("extension value is not an OCTET STRING".into());
            }
            if oid_equals(der, &id, &OID_BASIC_CONSTRAINTS) {
                if info.has_basic_constraints {
                    return Err("duplicate BasicConstraints extension".into());
                }
                info.has_basic_constraints = true;
                let bc = read_tlv(der, next.start, next.end)?;
                if bc.tag != 0x30 {
                    return Err("BasicConstraints is not a SEQUENCE".into());
                }
                let mut c = bc.start;
                if c < bc.end {
                    let first = read_tlv(der, c, bc.end)?;
                    if first.tag == 0x01 {
                        if first.end - first.start != 1 {
                            return Err("BasicConstraints cA is not one byte".into());
                        }
                        info.ca = der[first.start] != 0;
                        c = first.end;
                    }
                }
                if c < bc.end {
                    let pl = read_tlv(der, c, bc.end)?;
                    if pl.tag != 0x02 || pl.end - pl.start < 1 || pl.end - pl.start > 2 || (der[pl.start] & 0x80) != 0 {
                        return Err("BasicConstraints pathLenConstraint malformed".into());
                    }
                    let mut n: i64 = 0;
                    for i in pl.start..pl.end {
                        n = (n << 8) | der[i] as i64;
                    }
                    info.path_len = Some(n);
                    c = pl.end;
                }
                if c != bc.end {
                    return Err("BasicConstraints has trailing data".into());
                }
            } else if oid_equals(der, &id, &OID_KEY_USAGE) {
                if info.has_key_usage {
                    return Err("duplicate keyUsage extension".into());
                }
                info.has_key_usage = true;
                let bs = read_tlv(der, next.start, next.end)?;
                if bs.tag != 0x03 || bs.end - bs.start < 2 {
                    return Err("keyUsage is not a BIT STRING".into());
                }
                if der[bs.start] > 7 {
                    return Err("keyUsage BIT STRING has more than 7 unused bits".into());
                }
                info.key_cert_sign = (der[bs.start + 1] & 0x04) != 0;
            }
        }
    }
    Ok(info)
}

#[derive(Clone, Debug)]
pub struct CertExtension {
    pub oid: String,
    pub critical: bool,
    /// The extnValue OCTET STRING content.
    pub value: Vec<u8>,
}

fn oid_to_dotted(b: &[u8], t: &Tlv) -> Result<String, String> {
    if t.tag != 0x06 || t.end <= t.start {
        return Err("extension OID is malformed".into());
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut v: u128 = 0;
    let mut open = false;
    for i in t.start..t.end {
        let byte = b[i];
        if !open && byte == 0x80 {
            return Err("extension OID has a non-minimal arc".into());
        }
        if v >> 120 != 0 {
            return Err("extension OID is malformed".into());
        }
        v = (v << 7) | (byte & 0x7f) as u128;
        open = byte & 0x80 != 0;
        if !open {
            arcs.push(v);
            v = 0;
        }
    }
    if open {
        return Err("extension OID is truncated".into());
    }
    let first = arcs[0];
    let head: [u128; 2] = if first < 40 {
        [0, first]
    } else if first < 80 {
        [1, first - 40]
    } else {
        [2, first - 80]
    };
    let mut parts: Vec<String> = head.iter().map(|x| x.to_string()).collect();
    for a in &arcs[1..] {
        parts.push(a.to_string());
    }
    Ok(parts.join("."))
}

/// `parseTbsExtensions`: the STRICT extension table of a tbsCertificate (the DER SEQUENCE including its header).
pub fn parse_tbs_extensions(tbs_der: &[u8]) -> Result<Vec<CertExtension>, String> {
    let tbs = read_tlv(tbs_der, 0, tbs_der.len())?;
    if tbs.tag != 0x30 {
        return Err("tbsCertificate is not a SEQUENCE".into());
    }
    if tbs.end != tbs_der.len() {
        return Err("trailing bytes after tbsCertificate".into());
    }
    let mut out: Vec<CertExtension> = Vec::new();
    let mut seen = false;
    let mut block_end: usize = 0;
    let mut p = tbs.start;
    while p < tbs.end {
        let el = read_tlv(tbs_der, p, tbs.end)?;
        p = el.end;
        if el.tag != 0xa3 {
            continue;
        }
        if seen {
            return Err("duplicate [3] extensions block".into());
        }
        seen = true;
        block_end = el.end;
        let seq = read_tlv(tbs_der, el.start, el.end)?;
        if seq.tag != 0x30 {
            return Err("extensions is not a SEQUENCE".into());
        }
        if seq.end != el.end {
            return Err("trailing bytes after the Extensions SEQUENCE".into());
        }
        if seq.start == seq.end {
            return Err("empty Extensions SEQUENCE".into());
        }
        let mut q = seq.start;
        while q < seq.end {
            let ext = read_tlv(tbs_der, q, seq.end)?;
            q = ext.end;
            if ext.tag != 0x30 {
                return Err("extension is not a SEQUENCE".into());
            }
            let id = read_tlv(tbs_der, ext.start, ext.end)?;
            let dotted = oid_to_dotted(tbs_der, &id)?;
            let mut r = id.end;
            let mut next = read_tlv(tbs_der, r, ext.end)?;
            let mut critical = false;
            if next.tag == 0x01 {
                if next.end - next.start != 1 || tbs_der[next.start] != 0xff {
                    return Err(format!("extension {dotted} has a non-DER critical flag"));
                }
                critical = true;
                r = next.end;
                next = read_tlv(tbs_der, r, ext.end)?;
            }
            if next.tag != 0x04 {
                return Err(format!("extension {dotted} value is not an OCTET STRING"));
            }
            if next.end != ext.end {
                return Err(format!("extension {dotted} has trailing bytes"));
            }
            if out.iter().any(|e| e.oid == dotted) {
                return Err(format!("duplicate extension {dotted}"));
            }
            out.push(CertExtension { oid: dotted, critical, value: tbs_der[next.start..next.end].to_vec() });
        }
    }
    if seen && block_end != tbs.end {
        return Err("extensions block is not the last TBS element".into());
    }
    Ok(out)
}

/// `tbsOfCertificate`: the tbsCertificate bytes (header included); rejects trailing bytes after the certificate.
pub fn tbs_of_certificate(cert: &[u8]) -> Result<Vec<u8>, String> {
    let outer = read_tlv(cert, 0, cert.len())?;
    if outer.tag != 0x30 {
        return Err("certificate is not a DER SEQUENCE".into());
    }
    if outer.end != cert.len() {
        return Err("trailing bytes after the certificate".into());
    }
    let tbs = read_tlv(cert, outer.start, outer.end)?;
    if tbs.tag != 0x30 {
        return Err("certificate has no tbsCertificate".into());
    }
    Ok(cert[outer.start..tbs.end].to_vec())
}

pub fn parse_cert_extensions(cert: &[u8]) -> Result<Vec<CertExtension>, String> {
    parse_tbs_extensions(&tbs_of_certificate(cert)?)
}

pub fn find_ext<'a>(exts: &'a [CertExtension], oid: &str) -> Option<&'a CertExtension> {
    exts.iter().find(|e| e.oid == oid)
}

/// The only critical extensions the chain verifiers understand: BasicConstraints and keyUsage.
pub fn recognised_critical() -> HashSet<String> {
    ["2.5.29.19", "2.5.29.15"].iter().map(|s| s.to_string()).collect()
}

/// RFC 5280 4.2: the first critical extension the verifier does not recognise. Errors on a malformed extension table.
pub fn unrecognised_critical_extension(cert: &[u8], recognised: Option<&HashSet<String>>) -> Result<Option<String>, String> {
    let default = recognised_critical();
    let rec = recognised.unwrap_or(&default);
    for e in parse_cert_extensions(cert)? {
        if e.critical && !rec.contains(&e.oid) {
            return Ok(Some(e.oid));
        }
    }
    Ok(None)
}

/// `checkChainRoles`: CA roles over an ordered chain (index 0 = leaf ... last = self-signed root).
pub fn check_chain_roles(ordered: &[Vec<u8>]) -> Option<String> {
    let n = ordered.len();
    for i in 0..n {
        let info = match read_cert_role_info(&ordered[i]) {
            Ok(x) => x,
            Err(e) => return Some(format!("certificate extension parse failed: {e}")),
        };
        if i == 0 && n > 1 {
            if info.ca {
                return Some("leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)".into());
            }
            continue;
        }
        if i == 0 {
            continue;
        }
        if !info.has_basic_constraints {
            return Some(format!("issuer certificate at depth {i} has no BasicConstraints (not a CA)"));
        }
        if !info.ca {
            return Some(format!("issuer certificate at depth {i} is not a CA (BasicConstraints CA:FALSE)"));
        }
        if info.has_key_usage && !info.key_cert_sign {
            return Some(format!("issuer certificate at depth {i} keyUsage lacks keyCertSign"));
        }
        if let Some(pl) = info.path_len {
            if pl < i as i64 - 1 {
                return Some(format!("issuer certificate at depth {i} pathLenConstraint {pl} is exceeded ({} intermediate(s) below)", i - 1));
            }
        }
    }
    None
}

// ───────────────────────────── x509-validity.ts

/// `tlvAt` of x509-validity.ts (lengths of up to four octets, no minimality rules).
pub fn tlv_at(der: &[u8], off: usize) -> Result<Tlv, ()> {
    if off + 2 > der.len() {
        return Err(());
    }
    let tag = der[off];
    let mut len = der[off + 1] as usize;
    let mut start = off + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || start + n > der.len() {
            return Err(());
        }
        len = 0;
        for i in 0..n {
            len = len * 256 + der[start + i] as usize;
        }
        start += n;
    }
    let end = start + len;
    if end > der.len() {
        return Err(());
    }
    Ok(Tlv { tag, start, end })
}

/// Strict RFC 5280 Time: tag 0x17 UTCTime `YYMMDDHHMMSSZ` or tag 0x18 GeneralizedTime `YYYYMMDDHHMMSSZ`. `None` (NaN) otherwise.
pub fn parse_der_time(tag: u8, text: &str) -> Option<i64> {
    let t = text.as_bytes();
    let (y, rest): (i64, &[u8]) = if tag == 0x17 && t.len() == 13 {
        let yy = parse_digits(&t[0..2])?;
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &t[2..])
    } else if tag == 0x18 && t.len() == 15 {
        (parse_digits(&t[0..4])?, &t[4..])
    } else {
        return None;
    };
    if rest[10] != b'Z' || !t[..t.len() - 1].iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mon = parse_digits(&rest[0..2])?;
    let day = parse_digits(&rest[2..4])?;
    let h = parse_digits(&rest[4..6])?;
    let mi = parse_digits(&rest[6..8])?;
    let sec = parse_digits(&rest[8..10])?;
    civil_ms(y, mon, day, h, mi, sec, 0)
}

fn parse_digits(b: &[u8]) -> Option<i64> {
    if b.is_empty() || !b.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(b.iter().fold(0i64, |a, c| a * 10 + (*c - b'0') as i64))
}

/// `derValidityMs`: the `validity` instants of a DER certificate; `None` members when malformed.
pub fn der_validity_ms(der: &[u8]) -> (Option<i64>, Option<i64>) {
    fn inner(der: &[u8]) -> Result<(Option<i64>, Option<i64>), ()> {
        let cert = tlv_at(der, 0)?;
        if cert.tag != 0x30 {
            return Err(());
        }
        let tbs = tlv_at(der, cert.start)?;
        if tbs.tag != 0x30 {
            return Err(());
        }
        let mut el = tlv_at(der, tbs.start)?;
        if el.tag == 0xa0 {
            el = tlv_at(der, el.end)?;
        }
        if el.tag != 0x02 {
            return Err(());
        }
        el = tlv_at(der, el.end)?;
        if el.tag != 0x30 {
            return Err(());
        }
        el = tlv_at(der, el.end)?;
        if el.tag != 0x30 {
            return Err(());
        }
        let validity = tlv_at(der, el.end)?;
        if validity.tag != 0x30 || validity.end > tbs.end {
            return Err(());
        }
        let nb = tlv_at(der, validity.start)?;
        let na = tlv_at(der, nb.end)?;
        if na.end != validity.end {
            return Err(());
        }
        let text = |t: &Tlv| -> String { der[t.start..t.end].iter().map(|c| *c as char).collect() };
        Ok((parse_der_time(nb.tag, &text(&nb)), parse_der_time(na.tag, &text(&na))))
    }
    inner(der).unwrap_or((None, None))
}

/// `x509ValidAt`: both bounds parse and `from - skew <= now <= to + skew`; false (fail closed) otherwise.
pub fn x509_valid_at(der: &[u8], now_ms: f64, skew_ms: f64) -> bool {
    let (from, to) = der_validity_ms(der);
    match (from, to) {
        (Some(f), Some(t)) if now_ms.is_finite() && skew_ms.is_finite() => now_ms + skew_ms >= f as f64 && now_ms - skew_ms <= t as f64,
        _ => false,
    }
}

/// Lowercase hex helper re-exported for the vector replay of `parse_cert_extensions`.
pub fn ext_value_hex(e: &CertExtension) -> String {
    hex_lower(&e.value)
}
