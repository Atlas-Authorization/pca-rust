//! NVIDIA device-chain revocation through OCSP (RFC 6960): each response must verify for exactly one chain certificate
//! (issuer key or a delegated responder certificate signed by the NVIDIA chain), carry GOOD, and be fresh. Every
//! response the caller supplies is enforced; the certificates that advertise an OCSP responder must have a GOOD one.

use super::der::{der_validity_ms, find_ext, parse_cert_extensions, parse_cert_extensions_ber, tlv_at, Tlv};
use super::util::{civil_ms, sha1, sha256, sha384, sha512};
use super::x509::{name_to_string, verify_der_sig, Cert, Hash, PubKey};

const OID_OCSP_BASIC: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const OID_EKU_OCSP_SIGNING: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const OID_AD_OCSP: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
/// The default maximum age of a response (`NVIDIA_OCSP_DEFAULT_MAX_AGE_MS`).
pub const DEFAULT_MAX_AGE_MS: f64 = 7.0 * 24.0 * 3600.0 * 1000.0;
/// The default OCSP responder of NVIDIA's device identity chain.
pub const NVIDIA_OCSP_URL: &str = "http://ocsp.ndis.nvidia.com/";
/// asn1js `fromBER`'s `maxDepth`: the parsed root is depth 0 and an element below this refuses the whole read.
const MAX_BER_DEPTH: usize = 100;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Good,
    Revoked,
    Unknown,
    Absent,
}

/// `cand.checkIssued(s) && cand.verify(s.publicKey)`: name, the issuer's keyUsage if present, AKID against SKID, signature. An
/// extension table that does not parse has no link, as OpenSSL marks such a certificate invalid.
pub(crate) fn delegated_issued_by(cand: &Cert, s: &Cert) -> bool {
    delegated_issued_by_with(cand, s, false)
}

/// [`delegated_issued_by`] for a verifier whose reference reads certificates with OpenSSL (SPIFFE): a BER critical flag is accepted.
pub(crate) fn delegated_issued_by_ber(cand: &Cert, s: &Cert) -> bool {
    delegated_issued_by_with(cand, s, true)
}

fn delegated_issued_by_with(cand: &Cert, s: &Cert, ber: bool) -> bool {
    let parse = |c: &Cert| if ber { parse_cert_extensions_ber(&c.raw) } else { parse_cert_extensions(&c.raw) };
    let (ce, se) = match (parse(cand), parse(s)) {
        (Ok(c), Ok(s)) => (c, s),
        _ => return false,
    };
    let ku_ok = find_ext(&se, "2.5.29.15").map_or(true, |x| x.value.len() >= 4 && x.value[0] == 0x03 && (x.value[3] & 0x04) != 0);
    let ids = crate::sigstore::key_ids_link(find_ext(&ce, "2.5.29.35").map(|x| &x.value[..]), find_ext(&se, "2.5.29.14").map(|x| &x.value[..]), &s.serial, &s.issuer);
    cand.issuer == s.subject && ku_ok && ids && s.public_key().map_or(false, |k| cand.verify(&k))
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
        v = (v << 7) + (x & 0x7f) as u128;
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

pub(super) fn digest(h: Hash, m: &[u8]) -> Vec<u8> {
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
pub(super) fn key_bits(spki: &[u8]) -> Vec<u8> {
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

fn utc_year(yy: i64) -> i64 {
    if yy < 50 {
        2000 + yy
    } else {
        1900 + yy
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
        (utc_year(n(&b[0..2])), &b[2..12])
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

/// `allAsn1TimesWellFormed` (OCTET / BIT STRING nodes are opaque) over the tree `asn1js.fromBER` reads: `Err` is a read asn1js refuses (too deep, or an element that does
/// not parse), `Ok(false)` a malformed time. `depth` is the depth of the elements in `start..end`.
fn all_times_well_formed(b: &[u8], start: usize, end: usize, depth: usize) -> Result<bool, ()> {
    let mut p = start;
    while p < end {
        if depth > MAX_BER_DEPTH {
            return Err(());
        }
        let t = tlv_at(&b[..end], p)?;
        if t.tag == 0x18 || t.tag == 0x17 {
            let text: String = b[t.start..t.end].iter().map(|c| *c as char).collect();
            if !time_text_in_range(&text, t.tag == 0x17) {
                return Ok(false);
            }
        } else if t.tag & 0x20 != 0 {
            // OCTET / BIT STRING contents are opaque bytes (a hash, nonce or signature that happens to read as a bad time must not refuse a
            // valid response), primitive or constructed; a constructed one is still walked for the read errors asn1js raises, never for times.
            let opaque = t.tag == 0x23 || t.tag == 0x24;
            if !all_times_well_formed(b, t.start, t.end, depth + 1)? && !opaque {
                return Ok(false);
            }
        }
        p = t.end;
    }
    Ok(true)
}

/// A GeneralizedTime value in epoch milliseconds: asn1js reads the fraction as `Math.floor(1000 * Number("0." + digits))`.
fn time_ms(b: &[u8], t: &Tlv) -> Option<f64> {
    let s: String = b[t.start..t.end].iter().map(|c| *c as char).collect();
    let d = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse::<i64>().ok() };
    let mut ms = 0i64;
    if s.as_bytes().get(14) == Some(&b'.') {
        let frac: String = s[15..].chars().take_while(|c| c.is_ascii_digit()).collect();
        ms = (1000.0 * format!("0.{frac}").parse::<f64>().ok()?).floor() as i64;
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

/// The verified content of one response.
pub struct OcspOk {
    pub status: Status,
    pub this_update: f64,
    pub next_update: Option<f64>,
    pub produced_at: f64,
    /// Revoked only: when, and the CRL reason code when the response carries one.
    pub revoked_at: Option<f64>,
    pub revocation_reason: Option<i64>,
    /// Signed by a responder certificate the NVIDIA chain issued, rather than by the certificate's issuer itself.
    pub delegated: bool,
}

/// Options of one verification: the maximum accepted age, a clock skew tolerance and the nonce the response must echo.
#[derive(Clone, Debug)]
pub struct OcspOpts {
    pub max_age_ms: f64,
    pub clock_skew_ms: f64,
    pub expected_nonce: Option<Vec<u8>>,
}

impl Default for OcspOpts {
    fn default() -> Self {
        OcspOpts { max_age_ms: DEFAULT_MAX_AGE_MS, clock_skew_ms: 0.0, expected_nonce: None }
    }
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

/// Verify one DER OCSPResponse for `cert` (issued by `issuer`) with the default options. `Err` is the failure reason.
pub fn verify_ocsp_response(der: &[u8], cert: &Cert, issuer: &Cert, chain: &[Cert], now_ms: f64) -> Result<OcspOk, String> {
    verify_ocsp_response_with(der, cert, issuer, chain, now_ms, &OcspOpts::default())
}

/// [`verify_ocsp_response`] with explicit options (`maxAgeMs`, `clockSkewMs`, `expectedNonce`). `Err` is the failure reason.
pub fn verify_ocsp_response_with(der: &[u8], cert: &Cert, issuer: &Cert, chain: &[Cert], now_ms: f64, opts: &OcspOpts) -> Result<OcspOk, String> {
    let skew = opts.clock_skew_ms;
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
    if bk.len() < 3 || bk[0].tag != 0x30 || bk[1].tag != 0x30 || bk[2].tag != 0x03 || bk[2].end <= bk[2].start || bk.get(3).is_some_and(|c| c.tag != 0xa0) {
        return Err(schema_err("BasicOCSPResponse"));
    }
    // every part of the response except the embedded certificates: those are parsed one by one below, and a malformed one is refused
    // there with the reference's fixed text (a structural error inside a certificate must not read as a malformed response)
    for child in bk.iter().filter(|c| c.tag != 0xa0) {
        let from = child.start - header_before(basic_bytes, 0, child);
        if !all_times_well_formed(basic_bytes, from, child.end, 1).map_err(|_| "BasicOCSPResponse is not valid DER".to_string())? {
            return Err("response carries a malformed (out-of-range) ASN.1 time".into());
        }
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
    let rd = kids(basic_bytes, &tbs).map_err(|_| schema_err("BasicOCSPResponse"))?;
    let mut ix = 0usize;
    if rd.get(ix).map_or(false, |t| t.tag == 0xa0) {
        ix += 1;
    }
    let rid = *rd.get(ix).ok_or_else(|| schema_err("BasicOCSPResponse"))?;
    ix += 1;
    let produced = *rd.get(ix).ok_or_else(|| schema_err("BasicOCSPResponse"))?;
    ix += 1;
    let resp_list = *rd.get(ix).ok_or_else(|| schema_err("BasicOCSPResponse"))?;
    if (rid.tag != 0xa1 && rid.tag != 0xa2) || produced.tag != 0x18 || resp_list.tag != 0x30 {
        return Err(schema_err("BasicOCSPResponse"));
    }
    let singles = kids(basic_bytes, &resp_list).map_err(|_| schema_err("BasicOCSPResponse"))?;

    // CertID match: exactly one SingleResponse must speak for the certificate
    let subj_serial = strip_zeros(&cert.serial);
    let issuer_name = &issuer.subject;
    let issuer_key = key_bits(&issuer.spki);
    let mut matches: Vec<Vec<Tlv>> = Vec::new();
    for s in &singles {
        let sk = kids(basic_bytes, s).map_err(|_| schema_err("BasicOCSPResponse"))?;
        if sk.len() < 3 || sk[0].tag != 0x30 || sk[2].tag != 0x18 {
            return Err(schema_err("BasicOCSPResponse"));
        }
        // CHOICE { good [0] primitive, revoked [1] { GeneralizedTime, .. }, unknown [2] primitive }.
        let status_ok = match sk[1].tag {
            0x80 | 0x82 => true,
            0xa1 => kids(basic_bytes, &sk[1]).is_ok_and(|k| k.first().is_some_and(|t| t.tag == 0x18)),
            _ => false,
        };
        if !status_ok {
            return Err(schema_err("BasicOCSPResponse"));
        }
        // After thisUpdate only an optional [0] nextUpdate, then an optional [1] extensions: an unknown element must not hide a
        // nextUpdate from the stale check. Checked for every SingleResponse, as the reference's schema parses them all.
        let rest: Vec<u8> = sk[3..].iter().map(|t| t.tag).collect();
        if !matches!(rest[..], [] | [0xa0] | [0xa1] | [0xa0, 0xa1]) {
            return Err(schema_err("BasicOCSPResponse"));
        }
        if sk.get(3).is_some_and(|n| n.tag == 0xa0) {
            let inner = kids(basic_bytes, &sk[3]).map_err(|_| schema_err("BasicOCSPResponse"))?;
            if inner.len() != 1 || inner[0].tag != 0x18 {
                return Err(schema_err("BasicOCSPResponse"));
            }
        }
        let cid = kids(basic_bytes, &sk[0]).map_err(|_| schema_err("BasicOCSPResponse"))?;
        if cid.len() != 4 || cid[0].tag != 0x30 || cid[1].tag != 0x04 || cid[2].tag != 0x04 || cid[3].tag != 0x02 {
            return Err(schema_err("BasicOCSPResponse"));
        }
        let ha = kids(basic_bytes, &cid[0]).map_err(|_| schema_err("BasicOCSPResponse"))?;
        if ha.is_empty() || ha[0].tag != 0x06 {
            return Err(schema_err("BasicOCSPResponse"));
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
    let mut delegated = false;
    if !issuer_ok {
        let mut why = "no embedded responder certificate verifies the response".to_string();
        let mut found = false;
        let embedded: Vec<Vec<u8>> = match bk.get(3) {
            Some(c) => {
                let inner = tlv_at(basic_bytes, c.start).map_err(|_| schema_err("BasicOCSPResponse"))?;
                let list = kids(basic_bytes, &inner).map_err(|_| schema_err("BasicOCSPResponse"))?;
                let mut v = Vec::new();
                for t in list {
                    let off = t.start - header_before(basic_bytes, t.start, &t);
                    v.push(basic_bytes[off..t.end].to_vec());
                }
                v
            }
            None => Vec::new(),
        };
        for raw in &embedded {
            // fixed texts, as the reference (the parser's own message is OpenSSL's and differs by version and language), and like every
            // refusal of the reference's verifier they are reported as `OCSP response rejected: <message>`. OpenSSL decodes the whole
            // certificate, so a structural error anywhere inside it refuses it, not only in the fields read here.
            let not_der = || "OCSP response rejected: embedded certificate is not valid DER".to_string();
            if all_times_well_formed(raw, 0, raw.len(), 1).is_err() {
                return Err(not_der());
            }
            let cand = Cert::from_der(raw).map_err(|_| not_der())?;
            // the parsed certificate re-encodes to exactly the bytes in the response (no length that the parser merely recovered from)
            if !is_canonical_certificate(raw) {
                return Err("OCSP response rejected: embedded certificate is not canonical DER".into());
            }
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
                (Some(a), Some(b)) => (a as f64) - skew <= now_ms && now_ms <= (b as f64),
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
            let signed = signers.iter().any(|s| delegated_issued_by(&cand, s));
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
        delegated = true;
    }

    // the nonce the response must echo (the responseExtensions are the [1] member after the responses)
    if let Some(want) = &opts.expected_nonce {
        const OID_NONCE: [u8; 9] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
        let ext_list = rd.get(ix + 1).filter(|t| t.tag == 0xa1);
        let mut raw: Option<Vec<u8>> = None;
        if let Some(e) = ext_list {
            let inner = tlv_at(basic_bytes, e.start).map_err(|_| schema_err("BasicOCSPResponse"))?;
            for x in kids(basic_bytes, &inner).map_err(|_| schema_err("BasicOCSPResponse"))? {
                let parts = kids(basic_bytes, &x).map_err(|_| schema_err("BasicOCSPResponse"))?;
                if parts.first().is_some_and(|o| o.tag == 0x06 && basic_bytes[o.start..o.end] == OID_NONCE) {
                    raw = parts.last().filter(|v| v.tag == 0x04).map(|v| basic_bytes[v.start..v.end].to_vec());
                    break;
                }
            }
        }
        let Some(raw) = raw else { return Err("response does not echo the nonce".into()) };
        let echoed: Vec<u8> = match tlv_at(&raw, 0) {
            Ok(t) if t.tag == 0x04 && t.end == raw.len() => raw[t.start..t.end].to_vec(),
            _ => raw.clone(),
        };
        if echoed != *want {
            return Err("response nonce does not match the request nonce".into());
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
            let inner = tlv_at(basic_bytes, n.start).map_err(|_| schema_err("BasicOCSPResponse"))?;
            Some(time_ms(basic_bytes, &inner))
        }
        _ => None,
    };
    if !(now_ms.is_finite() && skew.is_finite() && this_update <= now_ms + skew) {
        return Err("response thisUpdate is in the future".into());
    }
    if !(produced_at <= now_ms + skew) {
        return Err("response producedAt is in the future".into());
    }
    if let Some(nu) = next_update {
        match nu {
            Some(n) if n >= this_update => {
                if !(now_ms <= n) {
                    return Err("response is stale (past nextUpdate)".into());
                }
            }
            _ => return Err("response nextUpdate is invalid".into()),
        }
    }
    if !(now_ms - this_update <= opts.max_age_ms) {
        return Err("response is older than the maximum accepted age".into());
    }
    let cs = single[1];
    let next_update = next_update.flatten();
    let mut ok = OcspOk { status: Status::Good, this_update, next_update, produced_at, revoked_at: None, revocation_reason: None, delegated };
    match cs.tag {
        0x80 => {}
        0x82 => ok.status = Status::Unknown,
        0xa1 => {
            // Its first child is a GeneralizedTime that passed the time check: 15 octets is revokedInfo's `^\d{14}Z$`.
            let first = tlv_at(basic_bytes, cs.start).ok().filter(|t| t.end - t.start == 15);
            let Some(first) = first else { return Err("malformed revoked certStatus".into()) };
            ok.status = Status::Revoked;
            ok.revoked_at = time_ms(basic_bytes, &first);
            // revocationReason [0] EXPLICIT CRLReason (an ENUMERATED), the second member of RevokedInfo
            let reason = kids(basic_bytes, &cs).ok().and_then(|k| k.get(1).copied()).filter(|t| t.tag == 0xa0).and_then(|t| tlv_at(basic_bytes, t.start).ok());
            ok.revocation_reason = reason.filter(|e| e.tag == 0x0a && e.end > e.start && e.end - e.start <= 6).map(|e| basic_bytes[e.start..e.end].iter().fold(0i64, |a, b| (a << 8) | *b as i64));
        }
        _ => return Err(schema_err("BasicOCSPResponse")),
    }
    Ok(ok)
}

/// The number of header octets in front of the content of `t` (so `t.start - header` is the start of the TLV).
/// The TLV at `off` when its length is written in the minimal DER form (the long form only for a length of at least 128, with no
/// leading zero octet).
fn minimal_tlv(der: &[u8], off: usize) -> Option<Tlv> {
    let t = tlv_at(der, off).ok()?;
    if der.get(off + 1)? & 0x80 != 0 && (t.end - t.start < 128 || *der.get(off + 2)? == 0) {
        return None;
    }
    Some(t)
}

fn children_minimal(der: &[u8], start: usize, end: usize) -> bool {
    let mut p = start;
    while p < end {
        let Some(t) = minimal_tlv(der, p) else { return false };
        if t.tag & 0x20 != 0 && !children_minimal(der, t.start, t.end) {
            return false;
        }
        p = t.end;
    }
    true
}

/// Does `der` (one parsed certificate) re-encode to exactly itself, as the reference's `X509Certificate.raw` does? OpenSSL keeps the
/// parsed to-be-signed bytes as they were and writes everything else again in DER: the outer header, the signature algorithm (with its
/// parameters) and the signature BIT STRING. Those must therefore already be minimal, and nothing may follow the certificate.
fn is_canonical_certificate(der: &[u8]) -> bool {
    let Some(outer) = minimal_tlv(der, 0) else { return false };
    if outer.end != der.len() {
        return false;
    }
    let Ok(tbs) = tlv_at(der, outer.start) else { return false };
    let Some(alg) = minimal_tlv(der, tbs.end) else { return false };
    if !children_minimal(der, alg.start, alg.end) {
        return false;
    }
    minimal_tlv(der, alg.end).is_some()
}

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

/// Which non-root chain certificates must carry a GOOD response (`requireGood`): by default every one that advertises an OCSP responder
/// (Authority Information Access), `All`, or the chain indices given on the wire (checked as integers against the chain).
#[derive(Clone, Debug, PartialEq)]
pub enum RequireGood {
    Aia,
    All,
    Indices(Vec<f64>),
}

/// The options of a chain check (`NvidiaChainOcspOptions`).
#[derive(Clone, Debug)]
pub struct ChainOcspOpts {
    pub require_good: RequireGood,
    pub max_age_ms: Option<f64>,
    pub clock_skew_ms: Option<f64>,
    /// Per chain index, the nonce that certificate's response must echo.
    pub expected_nonces: Vec<Option<Vec<u8>>>,
}

impl Default for ChainOcspOpts {
    fn default() -> Self {
        ChainOcspOpts { require_good: RequireGood::Aia, max_age_ms: None, clock_skew_ms: None, expected_nonces: Vec::new() }
    }
}

/// A successful chain check: the number of verified responses and the status per non-root chain certificate.
pub struct ChainOcspOk {
    pub verified_ocsp: usize,
    pub statuses: Vec<Status>,
}

/// A refused chain check: the reason and, once the per-certificate table exists, the statuses seen so far.
pub struct ChainOcspErr {
    pub reason: String,
    pub statuses: Option<Vec<Status>>,
}

/// `checkNvidiaChainOcsp`: every response the caller supplies is enforced (it must verify for exactly one chain certificate, once), and the
/// certificates the policy requires must have a GOOD one.
pub fn check_chain_ocsp_with(chain: &[Cert], responses: &[Vec<u8>], now_ms: f64, opts: &ChainOcspOpts) -> Result<ChainOcspOk, ChainOcspErr> {
    let early = |reason: String| ChainOcspErr { reason, statuses: None };
    if chain.len() < 2 {
        return Err(early("chain too short for OCSP".into()));
    }
    if responses.is_empty() {
        return Err(early("no OCSP responses supplied".into()));
    }
    let last = chain.len() - 1;
    let mut required: Vec<usize> = Vec::new();
    match &opts.require_good {
        RequireGood::Indices(list) => {
            for i in list {
                if !(i.is_finite() && i.fract() == 0.0 && *i >= 0.0 && (*i as usize) < last) {
                    return Err(early(format!("requireGood index {} is not a non-root chain certificate", crate::intent_v2::js_number_string(*i))));
                }
                if !required.contains(&(*i as usize)) {
                    required.push(*i as usize);
                }
            }
        }
        other => required = (0..last).filter(|i| *other == RequireGood::All || cert_has_ocsp_url(&chain[*i])).collect(),
    }
    let mut statuses: Vec<Status> = vec![Status::Absent; last];
    let mut verified = 0usize;
    let late = |reason: String, st: &[Status]| ChainOcspErr { reason, statuses: Some(st.to_vec()) };
    for (ri, der) in responses.iter().enumerate() {
        let mut matched = false;
        let mut last_reason = "matches no chain certificate".to_string();
        for i in 0..last {
            let one = OcspOpts {
                max_age_ms: opts.max_age_ms.unwrap_or(DEFAULT_MAX_AGE_MS),
                clock_skew_ms: opts.clock_skew_ms.unwrap_or(0.0),
                expected_nonce: opts.expected_nonces.get(i).cloned().flatten().filter(|n| !n.is_empty()),
            };
            match verify_ocsp_response_with(der, &chain[i], &chain[i + 1], chain, now_ms, &one) {
                Err(r) => {
                    if !r.starts_with("no SingleResponse matches") {
                        return Err(late(format!("OCSP response #{ri} for '{}' rejected: {r}", subj_line(&chain[i])), &statuses));
                    }
                    last_reason = r;
                }
                Ok(o) => {
                    if matched {
                        return Err(late(format!("OCSP response #{ri} matches more than one chain certificate"), &statuses));
                    }
                    matched = true;
                    if statuses[i] != Status::Absent {
                        return Err(late(format!("duplicate OCSP responses for chain certificate #{i}"), &statuses));
                    }
                    statuses[i] = o.status;
                    verified += 1;
                    if o.status == Status::Revoked {
                        return Err(late(format!("chain certificate '{}' is revoked (OCSP)", subj_line(&chain[i])), &statuses));
                    }
                }
            }
        }
        if !matched {
            return Err(late(format!("OCSP response #{ri} rejected: {last_reason}"), &statuses));
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
            return Err(late(format!("no GOOD OCSP response for required certificate '{}' (status: {name})", subj_line(&chain[i])), &statuses));
        }
    }
    Ok(ChainOcspOk { verified_ocsp: verified, statuses })
}

/// `checkNvidiaChainOcsp` with the default options (every non-root certificate that advertises a responder must have a
/// GOOD response; supplied responses are always enforced). `Err` is the reason; `Ok` the number of verified responses.
pub fn check_chain_ocsp(chain: &[Cert], responses: &[Vec<u8>], now_ms: f64) -> Result<usize, String> {
    check_chain_ocsp_with(chain, responses, now_ms, &ChainOcspOpts::default()).map(|o| o.verified_ocsp).map_err(|e| e.reason)
}

/// `nvidiaCertOcspUrls`: the OCSP responder URLs a certificate advertises (Authority Information Access, access method id-ad-ocsp,
/// uniformResourceIdentifier locations), in order. Empty when it has none or the extension does not parse.
pub fn cert_ocsp_urls(c: &Cert) -> Vec<String> {
    let Ok(exts) = parse_cert_extensions(&c.raw) else { return Vec::new() };
    let Some(ext) = find_ext(&exts, "1.3.6.1.5.5.7.1.1") else { return Vec::new() };
    let b = &ext.value;
    let Some(seq) = tlv_at(b, 0).ok().filter(|t| t.tag == 0x30) else { return Vec::new() };
    let Ok(list) = kids(b, &seq) else { return Vec::new() };
    list.iter()
        .filter_map(|ad| {
            let k = kids(b, ad).ok()?;
            (k.len() >= 2 && k[0].tag == 0x06 && b[k[0].start..k[0].end] == OID_AD_OCSP && k[1].tag == 0x86)
                .then(|| b[k[1].start..k[1].end].iter().map(|c| *c as char).collect::<String>())
        })
        .collect()
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// `buildNvidiaOcspRequest`: a DER OCSPRequest (RFC 6960) for `cert` issued by `issuer`, identifying it with a SHA-384 CertID unless
/// `hash` names another of `sha1`, `sha256`, `sha384`, `sha512`, with an optional nonce extension (1..32 bytes). `Err` for an unknown
/// hash or a nonce of the wrong length.
pub fn build_ocsp_request(cert: &Cert, issuer: &Cert, nonce: Option<&[u8]>, hash: Option<&str>) -> Result<Vec<u8>, String> {
    let (h, oid): (Hash, &[u8]) = match hash.unwrap_or("sha384") {
        "sha1" => (Hash::Sha1, &[0x2b, 0x0e, 0x03, 0x02, 0x1a]),
        "sha256" => (Hash::Sha256, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
        "sha384" => (Hash::Sha384, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
        "sha512" => (Hash::Sha512, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
        other => return Err(format!("Cannot read properties of undefined (hash '{other}')")),
    };
    let mut alg = der_wrap(0x06, oid);
    alg.extend_from_slice(&[0x05, 0x00]);
    let mut cert_id = der_wrap(0x30, &alg);
    cert_id.extend(der_wrap(0x04, &digest(h, &issuer.subject)));
    cert_id.extend(der_wrap(0x04, &digest(h, &key_bits(&issuer.spki))));
    cert_id.extend(der_wrap(0x02, &cert.serial));
    let request = der_wrap(0x30, &der_wrap(0x30, &cert_id));
    let mut tbs = der_wrap(0x30, &request);
    if let Some(n) = nonce {
        if n.is_empty() || n.len() > 32 {
            return Err("nonce must be 1..32 bytes".into());
        }
        let mut ext = der_wrap(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]);
        ext.extend(der_wrap(0x04, &der_wrap(0x04, n)));
        tbs.extend(der_wrap(0xa2, &der_wrap(0x30, &der_wrap(0x30, &ext))));
    }
    Ok(der_wrap(0x30, &der_wrap(0x30, &tbs)))
}

/// `allAsn1TimesWellFormed` over a DER value: every GeneralizedTime / UTCTime inside it is a well-formed DER time with in-range fields
/// (no calendar roll-over); OCTET STRING / BIT STRING contents are opaque. A value the ASN.1 reader itself refuses is `false`.
pub fn asn1_times_well_formed(der: &[u8]) -> bool {
    all_times_well_formed(der, 0, der.len(), 0).unwrap_or(false)
}

#[cfg(test)]
#[path = "base_ocsp_test.rs"]
mod base_ocsp_test;

#[cfg(test)]
mod embedded_certificate_tests {
    use super::*;

    /// One TLV with its length in the minimal DER form.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match body.len() {
            n if n < 128 => v.push(n as u8),
            n if n < 256 => v.extend_from_slice(&[0x81, n as u8]),
            n => v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
        }
        v.extend_from_slice(body);
        v
    }

    /// A structurally complete certificate (the signature is not valid; only the parse and the encoding are under test).
    fn certificate(wide_alg_length: bool) -> Vec<u8> {
        let oid = tlv(0x06, &[0x2b, 0x65, 0x70]);
        let alg = if wide_alg_length {
            // the same SEQUENCE with its length in the long form although it fits the short one
            let mut v = vec![0x30, 0x81, oid.len() as u8];
            v.extend_from_slice(&oid);
            v
        } else {
            tlv(0x30, &oid)
        };
        let name = tlv(0x30, &[]);
        let time = tlv(0x17, b"260101000000Z");
        let mut tbs_body = tlv(0x02, &[1]);
        tbs_body.extend(tlv(0x30, &oid));
        tbs_body.extend(&name);
        tbs_body.extend(tlv(0x30, &[time.clone(), time].concat()));
        tbs_body.extend(&name);
        tbs_body.extend(tlv(0x30, &[]));
        let tbs = tlv(0x30, &tbs_body);
        let sig = tlv(0x03, &[0u8; 100]);
        tlv(0x30, &[tbs, alg, sig].concat())
    }

    #[test]
    fn a_minimally_encoded_certificate_is_canonical() {
        let c = certificate(false);
        assert!(Cert::from_der(&c).is_ok());
        assert!(is_canonical_certificate(&c));
    }

    #[test]
    fn a_parseable_certificate_with_a_non_minimal_signature_algorithm_length_is_not_canonical() {
        let c = certificate(true);
        assert!(Cert::from_der(&c).is_ok(), "the parser recovers the length");
        assert!(!is_canonical_certificate(&c), "but the certificate does not re-encode to itself");
    }

    #[test]
    fn a_non_minimal_outer_length_or_trailing_bytes_are_not_canonical() {
        let c = certificate(false);
        assert_eq!(&c[..2], &[0x30, 0x81], "the outer length is the one-octet long form");
        // the outer length padded with a leading zero octet: 0x82 0x00 LL
        let mut wide = vec![0x30, 0x82, 0x00, c[2]];
        wide.extend_from_slice(&c[3..]);
        assert!(Cert::from_der(&wide).is_ok());
        assert!(!is_canonical_certificate(&wide));
        let mut trailing = c;
        trailing.push(0);
        assert!(!is_canonical_certificate(&trailing));
    }
}
