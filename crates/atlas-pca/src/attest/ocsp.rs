//! NVIDIA device-chain revocation through OCSP (RFC 6960): each response must verify for exactly one chain certificate
//! (issuer key or a delegated responder certificate signed by the NVIDIA chain), carry GOOD, and be fresh. Every
//! response the caller supplies is enforced; the certificates that advertise an OCSP responder must have a GOOD one.

use super::der::{der_validity_ms, find_ext, parse_cert_extensions, tlv_at, Tlv};
use super::util::{civil_ms, sha1, sha256, sha384, sha512};
use super::x509::{name_to_string, verify_der_sig, Cert, Hash, PubKey};

const OID_OCSP_BASIC: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const OID_EKU_OCSP_SIGNING: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const OID_AD_OCSP: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
const MAX_AGE_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Good,
    Revoked,
    Unknown,
    Absent,
}

fn schema_err(what: &str) -> String {
    format!("OCSP response rejected: Object's schema was not verified against input data for {what}")
}

fn kids(b: &[u8], t: &Tlv) -> Result<Vec<Tlv>, ()> {
    let mut out = Vec::new();
    let mut p = t.start;
    while p < t.end {
        let c = tlv_at(b, p)?;
        if c.end > t.end {
            return Err(());
        }
        out.push(c);
        p = c.end;
    }
    Ok(out)
}

fn full(b: &[u8], off: usize, t: &Tlv) -> Vec<u8> {
    b[off..t.end].to_vec()
}

fn dotted(b: &[u8]) -> String {
    let mut arcs: Vec<u128> = Vec::new();
    let mut v: u128 = 0;
    for x in b {
        v = (v << 7) | (x & 0x7f) as u128;
        if x & 0x80 == 0 {
            arcs.push(v);
            v = 0;
        }
    }
    if arcs.is_empty() {
        return String::new();
    }
    let f = arcs[0];
    let (a, c) = if f < 40 { (0, f) } else if f < 80 { (1, f - 40) } else { (2, f - 80) };
    let mut s = format!("{a}.{c}");
    for x in &arcs[1..] {
        s.push('.');
        s.push_str(&x.to_string());
    }
    s
}

fn hash_of_oid(o: &[u8]) -> Option<Hash> {
    match o {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => Some(Hash::Sha1),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Some(Hash::Sha256),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Some(Hash::Sha384),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Some(Hash::Sha512),
        _ => None,
    }
}

/// (hash, is EC) of an OCSP signature algorithm OID.
fn sig_alg(oid: &[u8]) -> Option<(Hash, bool)> {
    match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] => Some((Hash::Sha256, true)),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] => Some((Hash::Sha384, true)),
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04] => Some((Hash::Sha512, true)),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] => Some((Hash::Sha256, false)),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] => Some((Hash::Sha384, false)),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] => Some((Hash::Sha512, false)),
        _ => None,
    }
}

fn verify_sig(alg: (Hash, bool), tbs: &[u8], sig: &[u8], key: &PubKey) -> bool {
    let is_ec = matches!(key, PubKey::Ec { .. });
    if alg.1 != is_ec {
        return false;
    }
    if !alg.1 && !matches!(key, PubKey::Rsa { .. }) {
        return false;
    }
    verify_der_sig(key, alg.0, tbs, sig)
}

fn digest(h: Hash, m: &[u8]) -> Vec<u8> {
    match h {
        Hash::Sha1 => sha1(m),
        Hash::Sha256 => sha256(m),
        Hash::Sha384 => sha384(m),
        Hash::Sha512 => sha512(m),
    }
}

fn strip_zeros(b: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < b.len() && b[i] == 0 {
        i += 1;
    }
    b[i..].to_vec()
}

/// The bytes of the subjectPublicKey BIT STRING (without the unused-bits octet).
fn key_bits(spki: &[u8]) -> Vec<u8> {
    let outer = match tlv_at(spki, 0) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let alg = match tlv_at(spki, outer.start) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    match tlv_at(spki, alg.end) {
        Ok(b) if b.end > b.start => spki[b.start + 1..b.end].to_vec(),
        _ => Vec::new(),
    }
}

fn time_text_in_range(text: &str, utc: bool) -> bool {
    let b = text.as_bytes();
    let all = |s: &[u8]| s.iter().all(|c| c.is_ascii_digit());
    let n = |s: &[u8]| s.iter().fold(0i64, |a, c| a * 10 + (*c - b'0') as i64);
    let (y, rest): (i64, &[u8]) = if utc {
        if b.len() != 13 || b[12] != b'Z' || !all(&b[..12]) {
            return false;
        }
        let yy = n(&b[0..2]);
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, &b[2..12])
    } else {
        if b.len() < 15 || !all(&b[..14]) {
            return false;
        }
        let tail = &b[14..];
        let ok = tail == b"Z" || (tail.len() >= 3 && tail[0] == b'.' && tail[tail.len() - 1] == b'Z' && all(&tail[1..tail.len() - 1]) && tail[tail.len() - 2] != b'0');
        if !ok {
            return false;
        }
        (n(&b[0..4]), &b[4..14])
    };
    civil_ms(y, n(&rest[0..2]), n(&rest[2..4]), n(&rest[4..6]), n(&rest[6..8]), n(&rest[8..10]), 0).is_some()
}

fn all_times_well_formed(b: &[u8], start: usize, end: usize) -> bool {
    let mut p = start;
    while p < end {
        let t = match tlv_at(b, p) {
            Ok(t) => t,
            Err(_) => return true,
        };
        if t.tag == 0x18 || t.tag == 0x17 {
            let text: String = b[t.start..t.end].iter().map(|c| *c as char).collect();
            if !time_text_in_range(&text, t.tag == 0x17) {
                return false;
            }
        } else if t.tag & 0x20 != 0 && !all_times_well_formed(b, t.start, t.end) {
            return false;
        }
        p = t.end;
    }
    true
}

/// A GeneralizedTime / UTCTime value in epoch milliseconds (fraction truncated to milliseconds).
fn time_ms(b: &[u8], t: &Tlv) -> Option<f64> {
    let s: String = b[t.start..t.end].iter().map(|c| *c as char).collect();
    let d = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse::<i64>().ok() };
    if t.tag == 0x17 {
        let yy = d(0, 2)?;
        return civil_ms(if yy < 50 { 2000 + yy } else { 1900 + yy }, d(2, 4)?, d(4, 6)?, d(6, 8)?, d(8, 10)?, d(10, 12)?, 0).map(|x| x as f64);
    }
    let mut ms = 0i64;
    if s.as_bytes().get(14) == Some(&b'.') {
        let frac: String = s[15..].chars().take_while(|c| c.is_ascii_digit()).collect();
        let padded = format!("{frac:0<3}");
        ms = padded[..3].parse::<i64>().ok()?;
    }
    civil_ms(d(0, 4)?, d(4, 6)?, d(6, 8)?, d(8, 10)?, d(10, 12)?, d(12, 14)?, ms).map(|x| x as f64)
}

/// Does the certificate advertise an OCSP responder URL (Authority Information Access)?
pub fn cert_has_ocsp_url(c: &Cert) -> bool {
    let exts = match parse_cert_extensions(&c.raw) {
        Ok(e) => e,
        Err(_) => return false,
    };
    let ext = match find_ext(&exts, "1.3.6.1.5.5.7.1.1") {
        Some(e) => e,
        None => return false,
    };
    let b = &ext.value;
    let seq = match tlv_at(b, 0) {
        Ok(t) if t.tag == 0x30 => t,
        _ => return false,
    };
    let list = match kids(b, &seq) {
        Ok(l) => l,
        Err(_) => return false,
    };
    list.iter().any(|ad| {
        let k = match kids(b, ad) {
            Ok(k) => k,
            Err(_) => return false,
        };
        k.len() >= 2 && k[0].tag == 0x06 && b[k[0].start..k[0].end] == OID_AD_OCSP && k[1].tag == 0x86
    })
}

pub struct OcspOk {
    pub status: Status,
}

fn responder_matches(b: &[u8], rid: &Tlv, name_der: &[u8], key_hash_src: &[u8]) -> bool {
    match rid.tag {
        0xa1 => match tlv_at(b, rid.start) {
            Ok(n) => b[rid.start..n.end] == *name_der,
            Err(_) => false,
        },
        0xa2 => match tlv_at(b, rid.start) {
            Ok(o) if o.tag == 0x04 => b[o.start..o.end] == sha1(key_hash_src)[..],
            _ => false,
        },
        _ => false,
    }
}

/// Verify one DER OCSPResponse for `cert` (issued by `issuer`). `Err` is the failure reason.
pub fn verify_ocsp_response(der: &[u8], cert: &Cert, issuer: &Cert, chain: &[Cert], now_ms: f64) -> Result<OcspOk, String> {
    let top = tlv_at(der, 0).map_err(|_| "response is not valid DER".to_string())?;
    if top.end != der.len() {
        return Err("trailing bytes after OCSPResponse".into());
    }
    if top.tag != 0x30 {
        return Err(schema_err("OCSPResponse"));
    }
    let tk = kids(der, &top).map_err(|_| "response is not valid DER".to_string())?;
    if tk.is_empty() || tk[0].tag != 0x0a || tk[0].end - tk[0].start != 1 {
        return Err(schema_err("OCSPResponse"));
    }
    let status = der[tk[0].start];
    if status != 0 {
        return Err(format!("OCSP responseStatus is {status} (not successful)"));
    }
    if tk.len() < 2 || tk[1].tag != 0xa0 {
        return Err("successful response carries no responseBytes".into());
    }
    let rb = tlv_at(der, tk[1].start).map_err(|_| schema_err("OCSPResponse"))?;
    let rbk = kids(der, &rb).map_err(|_| schema_err("OCSPResponse"))?;
    if rb.tag != 0x30 || rbk.len() != 2 || rbk[0].tag != 0x06 || rbk[1].tag != 0x04 {
        return Err(schema_err("OCSPResponse"));
    }
    if der[rbk[0].start..rbk[0].end] != OID_OCSP_BASIC {
        return Err("responseType is not id-pkix-ocsp-basic".into());
    }
    let basic_bytes = &der[rbk[1].start..rbk[1].end];
    let basic = tlv_at(basic_bytes, 0).map_err(|_| "BasicOCSPResponse is not valid DER".to_string())?;
    if basic.tag != 0x30 {
        return Err(schema_err("BasicOCSPResponse"));
    }
    let bk = kids(basic_bytes, &basic).map_err(|_| schema_err("BasicOCSPResponse"))?;
    if bk.len() < 3 || bk[0].tag != 0x30 || bk[1].tag != 0x30 || bk[2].tag != 0x03 || bk[2].end <= bk[2].start {
        return Err(schema_err("BasicOCSPResponse"));
    }
    if !all_times_well_formed(basic_bytes, basic.start, basic.end) {
        return Err("response carries a malformed (out-of-range) ASN.1 time".into());
    }
    let tbs = bk[0];
    let tbs_bytes = full(basic_bytes, tbs.start - header_before(basic_bytes, 0, &tbs), &tbs);
    let alg_k = kids(basic_bytes, &bk[1]).map_err(|_| schema_err("BasicOCSPResponse"))?;
    if alg_k.is_empty() || alg_k[0].tag != 0x06 {
        return Err(schema_err("BasicOCSPResponse"));
    }
    let alg_oid = &basic_bytes[alg_k[0].start..alg_k[0].end];
    let alg = match sig_alg(alg_oid) {
        Some(a) => a,
        None => return Err(format!("unsupported OCSP signature algorithm {}", dotted(alg_oid))),
    };
    let sig = basic_bytes[bk[2].start + 1..bk[2].end].to_vec();

    // ResponseData
    let rd = kids(basic_bytes, &tbs).map_err(|_| schema_err("ResponseData"))?;
    let mut ix = 0usize;
    if rd.get(ix).map_or(false, |t| t.tag == 0xa0) {
        ix += 1;
    }
    let rid = *rd.get(ix).ok_or_else(|| schema_err("ResponseData"))?;
    ix += 1;
    let produced = *rd.get(ix).ok_or_else(|| schema_err("ResponseData"))?;
    ix += 1;
    let resp_list = *rd.get(ix).ok_or_else(|| schema_err("ResponseData"))?;
    if (rid.tag != 0xa1 && rid.tag != 0xa2) || produced.tag != 0x18 || resp_list.tag != 0x30 {
        return Err(schema_err("ResponseData"));
    }
    let singles = kids(basic_bytes, &resp_list).map_err(|_| schema_err("ResponseData"))?;

    // CertID match: exactly one SingleResponse must speak for the certificate
    let subj_serial = strip_zeros(&cert.serial);
    let issuer_name = &issuer.subject;
    let issuer_key = key_bits(&issuer.spki);
    let mut matches: Vec<Vec<Tlv>> = Vec::new();
    for s in &singles {
        let sk = kids(basic_bytes, s).map_err(|_| schema_err("SingleResponse"))?;
        if sk.len() < 3 || sk[0].tag != 0x30 {
            return Err(schema_err("SingleResponse"));
        }
        let cid = kids(basic_bytes, &sk[0]).map_err(|_| schema_err("CertID"))?;
        if cid.len() != 4 || cid[0].tag != 0x30 || cid[1].tag != 0x04 || cid[2].tag != 0x04 || cid[3].tag != 0x02 {
            return Err(schema_err("CertID"));
        }
        let ha = kids(basic_bytes, &cid[0]).map_err(|_| schema_err("CertID"))?;
        if ha.is_empty() || ha[0].tag != 0x06 {
            return Err(schema_err("CertID"));
        }
        let h = match hash_of_oid(&basic_bytes[ha[0].start..ha[0].end]) {
            Some(h) => h,
            None => continue,
        };
        let same = strip_zeros(&basic_bytes[cid[3].start..cid[3].end]) == subj_serial
            && basic_bytes[cid[1].start..cid[1].end] == digest(h, issuer_name)[..]
            && basic_bytes[cid[2].start..cid[2].end] == digest(h, &issuer_key)[..];
        if same {
            matches.push(sk);
        }
    }
    if matches.is_empty() {
        return Err("no SingleResponse matches the certificate (serial / issuer hashes differ)".into());
    }
    if matches.len() > 1 {
        return Err("ambiguous: multiple SingleResponses match the certificate".into());
    }
    let single = &matches[0];

    // responder authentication
    let issuer_pub = issuer.public_key()?;
    let is_issuer_id = responder_matches(basic_bytes, &rid, &issuer.subject, &key_bits(&issuer.spki));
    let issuer_ok = is_issuer_id && verify_sig(alg, &tbs_bytes, &sig, &issuer_pub);
    if !issuer_ok {
        let mut why = "no embedded responder certificate verifies the response".to_string();
        let mut found = false;
        let embedded: Vec<Vec<u8>> = match bk.get(3) {
            Some(c) if c.tag == 0xa0 => {
                let inner = tlv_at(basic_bytes, c.start).map_err(|_| schema_err("BasicOCSPResponse"))?;
                let list = kids(basic_bytes, &inner).map_err(|_| schema_err("BasicOCSPResponse"))?;
                let mut v = Vec::new();
                for t in list {
                    let off = t.start - header_before(basic_bytes, t.start, &t);
                    v.push(basic_bytes[off..t.end].to_vec());
                }
                v
            }
            _ => Vec::new(),
        };
        for raw in &embedded {
            let cand = Cert::from_der(raw).map_err(|e| format!("OCSP response rejected: {e}"))?;
            if !responder_matches(basic_bytes, &rid, &cand.subject, &key_bits(&cand.spki)) {
                why = "embedded certificates do not match the responderID".into();
                continue;
            }
            let has_eku = match parse_cert_extensions(&cand.raw) {
                Ok(exts) => match find_ext(&exts, "2.5.29.37") {
                    Some(e) => tlv_at(&e.value, 0).ok().and_then(|s| kids(&e.value, &s).ok()).map_or(false, |k| k.iter().any(|o| o.tag == 0x06 && e.value[o.start..o.end] == OID_EKU_OCSP_SIGNING)),
                    None => false,
                },
                Err(_) => false,
            };
            if !has_eku {
                why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU".into();
                continue;
            }
            let (nb, na) = der_validity_ms(&cand.raw);
            let in_window = match (nb, na) {
                (Some(a), Some(b)) => (a as f64) <= now_ms && now_ms <= (b as f64),
                _ => false,
            };
            if !in_window {
                why = "delegated responder certificate is outside its validity window".into();
                continue;
            }
            let idx = chain.iter().position(|c| c.raw == issuer.raw);
            let signers: Vec<&Cert> = match idx {
                Some(i) => chain[i..].iter().collect(),
                None => vec![issuer],
            };
            let signed = signers.iter().any(|s| {
                let ku_ok = match parse_cert_extensions(&s.raw).ok().and_then(|e| find_ext(&e, "2.5.29.15").map(|x| x.value.clone())) {
                    Some(v) => v.len() >= 4 && v[0] == 0x03 && (v[3] & 0x04) != 0,
                    None => true,
                };
                cand.issuer == s.subject && ku_ok && s.public_key().map_or(false, |k| cand.verify(&k))
            });
            if !signed {
                why = "delegated responder certificate is not signed by the supplied NVIDIA chain".into();
                continue;
            }
            if !verify_sig(alg, &tbs_bytes, &sig, &cand.public_key()?) {
                why = "OCSP response signature does not verify under the delegated responder key".into();
                continue;
            }
            found = true;
            break;
        }
        if !found {
            return Err(if is_issuer_id { "OCSP response signature does not verify under the issuer key".to_string() } else { why });
        }
    }

    // freshness
    let this_update = time_ms(basic_bytes, &single[2]);
    let produced_at = time_ms(basic_bytes, &produced);
    let (this_update, produced_at) = match (this_update, produced_at) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err("response times are not parseable".into()),
    };
    let next_update = match single.get(3) {
        Some(n) if n.tag == 0xa0 => {
            let inner = tlv_at(basic_bytes, n.start).map_err(|_| schema_err("SingleResponse"))?;
            Some(time_ms(basic_bytes, &inner))
        }
        _ => None,
    };
    if this_update > now_ms {
        return Err("response thisUpdate is in the future".into());
    }
    if produced_at > now_ms {
        return Err("response producedAt is in the future".into());
    }
    if let Some(nu) = next_update {
        match nu {
            Some(n) if n >= this_update => {
                if now_ms > n {
                    return Err("response is stale (past nextUpdate)".into());
                }
            }
            _ => return Err("response nextUpdate is invalid".into()),
        }
    }
    if now_ms - this_update > MAX_AGE_MS {
        return Err("response is older than the maximum accepted age".into());
    }
    let cs = single[1];
    let st = match cs.tag {
        0x80 => Status::Good,
        0x82 => Status::Unknown,
        0xa1 => {
            let k = kids(basic_bytes, &cs).map_err(|_| "malformed revoked certStatus".to_string())?;
            let ok = k.first().map_or(false, |t| {
                let txt: String = basic_bytes[t.start..t.end].iter().map(|c| *c as char).collect();
                t.tag == 0x18 && txt.len() == 15 && txt.ends_with('Z') && txt[..14].bytes().all(|c| c.is_ascii_digit())
            });
            if !ok {
                return Err("malformed revoked certStatus".into());
            }
            Status::Revoked
        }
        _ => {
            if cs.tag & 0xc0 != 0x80 {
                return Err("malformed certStatus".into());
            }
            return Err("unrecognised certStatus".into());
        }
    };
    Ok(OcspOk { status: st })
}

/// The number of header octets in front of the content of `t` (so `t.start - header` is the start of the TLV).
fn header_before(b: &[u8], _scan_from: usize, t: &Tlv) -> usize {
    for hl in 2..=6usize {
        if t.start >= hl {
            if let Ok(x) = tlv_at(b, t.start - hl) {
                if x.start == t.start && x.end == t.end {
                    return hl;
                }
            }
        }
    }
    2
}

fn subj_line(c: &Cert) -> String {
    name_to_string(&c.subject).replace('\n', ", ")
}

/// `checkNvidiaChainOcsp` with the default options (every non-root certificate that advertises a responder must have a
/// GOOD response; supplied responses are always enforced). `Err` is the reason; `Ok` the number of verified responses.
pub fn check_chain_ocsp(chain: &[Cert], responses: &[Vec<u8>], now_ms: f64) -> Result<usize, String> {
    if chain.len() < 2 {
        return Err("chain too short for OCSP".into());
    }
    if responses.is_empty() {
        return Err("no OCSP responses supplied".into());
    }
    let last = chain.len() - 1;
    let required: Vec<usize> = (0..last).filter(|i| cert_has_ocsp_url(&chain[*i])).collect();
    let mut statuses: Vec<Status> = vec![Status::Absent; last];
    let mut verified = 0usize;
    for (ri, der) in responses.iter().enumerate() {
        let mut matched = false;
        let mut last_reason = "matches no chain certificate".to_string();
        for i in 0..last {
            match verify_ocsp_response(der, &chain[i], &chain[i + 1], chain, now_ms) {
                Err(r) => {
                    if !r.starts_with("no SingleResponse matches") {
                        return Err(format!("OCSP response #{ri} for '{}' rejected: {r}", subj_line(&chain[i])));
                    }
                    last_reason = r;
                }
                Ok(o) => {
                    if matched {
                        return Err(format!("OCSP response #{ri} matches more than one chain certificate"));
                    }
                    matched = true;
                    if statuses[i] != Status::Absent {
                        return Err(format!("duplicate OCSP responses for chain certificate #{i}"));
                    }
                    statuses[i] = o.status;
                    verified += 1;
                    if o.status == Status::Revoked {
                        return Err(format!("chain certificate '{}' is revoked (OCSP)", subj_line(&chain[i])));
                    }
                }
            }
        }
        if !matched {
            return Err(format!("OCSP response #{ri} rejected: {last_reason}"));
        }
    }
    for i in required {
        if statuses[i] != Status::Good {
            let name = match statuses[i] {
                Status::Good => "good",
                Status::Revoked => "revoked",
                Status::Unknown => "unknown",
                Status::Absent => "absent",
            };
            return Err(format!("no GOOD OCSP response for required certificate '{}' (status: {name})", subj_line(&chain[i])));
        }
    }
    Ok(verified)
}
