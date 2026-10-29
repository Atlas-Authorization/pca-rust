//! Offline Sigstore bundle verification for build provenance (track K9): a port of packages/pca-attest-eat/src/sigstore.ts.
//!
//! Verifies a Sigstore bundle (v0.2 / v0.3, keyless, a DSSE in-toto envelope) against a pinned `trusted_root.json` with no
//! network: RFC 3161 timestamps (every one must verify) and the Rekor v1 SET as time sources; one Rekor v1 `dsse` 0.0.1 /
//! `intoto` 0.0.2 or Rekor v2 `hashedrekord` 0.0.2 entry with an RFC 9162 inclusion proof to a checkpoint signed by the
//! pinned log; the certificate path to a pinned Fulcio CA at every verified time; the embedded SCT when the root lists CT
//! logs; the entry body naming this envelope; the DSSE signature; the Fulcio identity extensions; the in-toto Statement.
//! [`verify_sigstore_bundle`] then reads the SLSA v1 predicate into the facts [`crate::provenance_gate`] checks.
//!
//! Why a port: the `sigstore` crate (0.14) verifies neither inclusion proofs nor SETs offline (both are TODOs in its bundle
//! verifier), has no RFC 3161 or Rekor v2 support, is async and pulls an HTTP/TLS stack. This module reuses the crate's own
//! X.509 / ECDSA / RSA / Ed25519 readers instead. Total: hostile input is a refusal, never a panic.

use serde_json::{json, Map, Value};

use crate::attest::der::der_validity_ms;
use crate::attest::util::{b64_strict, parse_iso_ms, sha256};
use crate::attest::x509::{der_wrap, parse_spki, verify_der_sig, Cert, EcCurve, Hash, PubKey};
use crate::{rfc9162_leaf_hash, verify_rfc9162_inclusion, INTOTO_STATEMENT_V1, SLSA_PROVENANCE_V1};

pub const SIGSTORE_BUNDLE_MEDIA_TYPES: [&str; 3] =
    ["application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle+json;version=0.3", "application/vnd.dev.sigstore.bundle.v0.3+json"];
pub const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const OID_SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.2";
const OID_SAN: &str = "2.5.29.17";
const OID_EKU: &str = "2.5.29.37";
const OID_AKI: &str = "2.5.29.35";
const OID_SKI: &str = "2.5.29.14";
const EKU_CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
const EKU_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";

type R<T> = Result<T, String>;

// ------------------------------------------------------------------------------------------------ trusted root

#[derive(Clone, Copy, Debug)]
struct Validity {
    start: i64,
    end: i64,
}
impl Validity {
    fn has(&self, at: i64) -> bool {
        self.start <= at && at <= self.end
    }
}

/// A pinned log. `v2` logs (Ed25519, C2SP signed-note checkpoints) carry the note name: the host of their base URL.
#[derive(Clone, Debug)]
pub struct PinnedLog {
    key_id: Vec<u8>,
    key: PubKey,
    valid: Validity,
    v2_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PinnedCa {
    chain: Vec<Cert>,
    valid: Validity,
}

/// A parsed `trusted_root.json`: transparency logs, CT logs, Fulcio CAs, timestamp authorities.
#[derive(Clone, Debug)]
pub struct PinnedRoots {
    tlogs: Vec<PinnedLog>,
    ctlogs: Vec<PinnedLog>,
    cas: Vec<PinnedCa>,
    tsas: Vec<PinnedCa>,
}

fn b64(v: Option<&Value>) -> R<Vec<u8>> {
    v.and_then(Value::as_str).and_then(b64_strict).ok_or_else(|| "not base64".to_string())
}
fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}
fn validity(v: Option<&Value>) -> R<Validity> {
    let o = obj(v);
    let start = o.and_then(|o| o.get("start")).and_then(Value::as_str).and_then(parse_iso_ms).ok_or("validFor.start missing")?;
    let end = match o.and_then(|o| o.get("end")) {
        Some(Value::String(s)) => parse_iso_ms(s).ok_or("validFor.end malformed")?,
        _ => i64::MAX,
    };
    Ok(Validity { start, end })
}

/// The host of a URL (`new URL(u).hostname`, for the http(s) URLs a trusted root carries).
fn hostname(u: &str) -> Option<String> {
    let rest = u.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let auth = auth.rsplit_once('@').map_or(auth, |x| x.1);
    let host = if auth.starts_with('[') { auth.split_inclusive(']').next()? } else { auth.split(':').next()? };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// An RSAPublicKey (PKCS#1) DER to a key.
fn pkcs1_rsa(der: &[u8]) -> R<PubKey> {
    let seq = tlv(der, 0, der.len())?;
    let k = kids(der, &seq)?;
    if seq.tag != 0x30 || seq.end != der.len() || k.len() != 2 || k[0].tag != 0x02 || k[1].tag != 0x02 {
        return Err("RSA key malformed".into());
    }
    let strip = |t: &T| der[t.body..t.end].iter().copied().skip_while(|b| *b == 0).collect::<Vec<u8>>();
    Ok(PubKey::Rsa { n: strip(&k[0]), e: strip(&k[1]) })
}

fn pinned_log(t: &Value, transparency: bool) -> R<Option<PinnedLog>> {
    let pk = obj(t.get("publicKey")).ok_or("log entry malformed")?;
    let lid = obj(t.get("logId")).ok_or("log entry malformed")?;
    let der = b64(pk.get("rawBytes"))?;
    let key_id = b64(lid.get("keyId"))?;
    let valid = validity(pk.get("validFor"))?;
    match pk.get("keyDetails").and_then(Value::as_str) {
        Some("PKIX_ECDSA_P256_SHA_256") => {
            if sha256(&der) != key_id {
                return Err("log id is not the SHA-256 of its key".into());
            }
            Ok(Some(PinnedLog { key_id, key: parse_spki(&der)?, valid, v2_name: None }))
        }
        Some("PKCS1_RSA_PKCS1V5") if !transparency => {
            let key = pkcs1_rsa(&der)?;
            if sha256(&key.spki_der()) != key_id {
                return Err("log id is not the SHA-256 of its key".into());
            }
            Ok(Some(PinnedLog { key_id, key, valid, v2_name: None }))
        }
        Some("PKIX_ED25519") if transparency => {
            let key = parse_spki(&der)?;
            let raw = match &key {
                PubKey::Ed25519(k) if k.len() == 32 => k.clone(),
                _ => return Err("not an Ed25519 key".into()),
            };
            let name = t.get("baseUrl").and_then(Value::as_str).and_then(hostname).unwrap_or_default();
            let mut m = format!("{name}\n").into_bytes();
            m.push(1);
            m.extend_from_slice(&raw);
            if name.is_empty() || sha256(&m) != key_id {
                return Err("log id is not the signed-note key hash of its key".into());
            }
            Ok(Some(PinnedLog { key_id, key, valid, v2_name: Some(name) }))
        }
        _ => Ok(None),
    }
}

fn pinned_chain(c: &Value) -> R<PinnedCa> {
    let certs = obj(c.get("certChain")).and_then(|o| o.get("certificates")).and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or("certificate authority entry malformed")?;
    let chain = certs.iter().map(|x| b64(x.get("rawBytes")).and_then(|d| full_cert(&d))).collect::<R<Vec<Cert>>>()?;
    Ok(PinnedCa { chain, valid: validity(c.get("validFor"))? })
}

fn full_cert(der: &[u8]) -> R<Cert> {
    let c = Cert::from_der(der)?;
    if c.raw.len() != der.len() {
        return Err("trailing bytes after the certificate".into());
    }
    Ok(c)
}

/// Parse a Sigstore `trusted_root.json` (`application/vnd.dev.sigstore.trustedroot+json;version=0.1`). A root with no CT log
/// means its owner does not require SCTs; otherwise an SCT from a pinned CT log is required.
pub fn parse_trusted_root(json: &Value) -> Result<PinnedRoots, String> {
    let o = json.as_object().filter(|o| o.get("mediaType").and_then(Value::as_str) == Some("application/vnd.dev.sigstore.trustedroot+json;version=0.1")).ok_or("not a trusted root v0.1")?;
    let arr = |k: &str| o.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let mut tlogs = Vec::new();
    for t in arr("tlogs") {
        tlogs.extend(pinned_log(&t, true)?);
    }
    let mut ctlogs = Vec::new();
    for t in arr("ctlogs") {
        ctlogs.extend(pinned_log(&t, false)?);
    }
    let cas = arr("certificateAuthorities").iter().map(pinned_chain).collect::<R<Vec<_>>>()?;
    let tsas = arr("timestampAuthorities").iter().map(pinned_chain).collect::<R<Vec<_>>>()?;
    if tlogs.is_empty() || cas.is_empty() {
        return Err("a trusted root needs a transparency log and a CA".into());
    }
    Ok(PinnedRoots { tlogs, ctlogs, cas, tsas })
}

// ------------------------------------------------------------------------------------------------ DER

#[derive(Clone, Copy, Debug, PartialEq)]
struct T {
    tag: u8,
    start: usize,
    body: usize,
    end: usize,
}

fn tlv(b: &[u8], off: usize, limit: usize) -> R<T> {
    let limit = limit.min(b.len());
    if off + 2 > limit {
        return Err("DER truncated".into());
    }
    let tag = b[off];
    if tag & 0x1f == 0x1f {
        return Err("DER multi-byte tag".into());
    }
    let mut len = b[off + 1] as usize;
    let mut body = off + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 || body + n > limit {
            return Err("DER length".into());
        }
        len = 0;
        for i in 0..n {
            len = len * 256 + b[body + i] as usize;
        }
        body += n;
    }
    if len > limit - body {
        return Err("DER overrun".into());
    }
    Ok(T { tag, start: off, body, end: body + len })
}
fn kids(b: &[u8], t: &T) -> R<Vec<T>> {
    let mut out = Vec::new();
    let mut o = t.body;
    while o < t.end {
        let c = tlv(b, o, t.end)?;
        o = c.end;
        out.push(c);
    }
    Ok(out)
}
fn kid(b: &[u8], t: &T, i: usize) -> R<T> {
    kids(b, t)?.get(i).copied().ok_or_else(|| "DER element missing".to_string())
}
fn oid_text(b: &[u8], t: &T) -> R<String> {
    if t.tag != 0x06 || t.end <= t.body {
        return Err("not an OID".into());
    }
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for &x in &b[t.body..t.end] {
        v = v.checked_mul(128).ok_or("OID arc too large")? + (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    let first = *parts.first().ok_or("not an OID")?;
    let a = (first / 40).min(2);
    let mut s = format!("{}.{}", a, first - a * 40);
    for p in &parts[1..] {
        s.push_str(&format!(".{p}"));
    }
    Ok(s)
}

struct Ext {
    oid: String,
    value: Vec<u8>,
    t: T,
}
struct ParsedCert {
    der: Vec<u8>,
    tbs_kids: Vec<T>,
    exts_wrapper: T,
    exts: Vec<Ext>,
}
fn parse_cert(der: &[u8]) -> R<ParsedCert> {
    let cert = tlv(der, 0, der.len())?;
    if cert.tag != 0x30 || cert.end != der.len() {
        return Err("certificate is not one SEQUENCE".into());
    }
    let tbs = kid(der, &cert, 0)?;
    if tbs.tag != 0x30 {
        return Err("no TBSCertificate".into());
    }
    let tbs_kids = kids(der, &tbs)?;
    let exts_wrapper = *tbs_kids.iter().find(|k| k.tag == 0xa3).ok_or("no extensions")?;
    let seq = kid(der, &exts_wrapper, 0)?;
    if seq.tag != 0x30 {
        return Err("extensions malformed".into());
    }
    let mut exts: Vec<Ext> = Vec::new();
    for e in kids(der, &seq)? {
        let parts = kids(der, &e)?;
        let (first, oct) = match (parts.first(), parts.last()) {
            (Some(f), Some(l)) => (f, l),
            _ => return Err("extension malformed".into()),
        };
        if oct.tag != 0x04 {
            return Err("extension value is not an OCTET STRING".into());
        }
        let oid = oid_text(der, first)?;
        if exts.iter().any(|x| x.oid == oid) {
            return Err(format!("duplicate extension {oid}"));
        }
        exts.push(Ext { oid, value: der[oct.body..oct.end].to_vec(), t: e });
    }
    Ok(ParsedCert { der: der.to_vec(), tbs_kids, exts_wrapper, exts })
}
impl ParsedCert {
    fn ext(&self, oid: &str) -> Option<&Ext> {
        self.exts.iter().find(|e| e.oid == oid)
    }
    fn has_eku(&self, eku: &str) -> bool {
        let Some(e) = self.ext(OID_EKU) else { return false };
        let Ok(seq) = tlv(&e.value, 0, e.value.len()) else { return false };
        kids(&e.value, &seq).map_or(false, |k| k.iter().any(|o| oid_text(&e.value, o).as_deref() == Ok(eku)))
    }
}

fn utf8(b: &[u8]) -> R<String> {
    String::from_utf8(b.to_vec()).map_err(|_| "not UTF-8".to_string())
}
/// Fulcio extension `.1.n`: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8 (fulcio docs/oid-info.md).
fn fulcio_ext(c: &ParsedCert, n: u32) -> R<Option<String>> {
    let Some(e) = c.ext(&format!("1.3.6.1.4.1.57264.1.{n}")) else { return Ok(None) };
    if n <= 6 {
        return utf8(&e.value).map(Some);
    }
    let t = tlv(&e.value, 0, e.value.len())?;
    if t.tag != 0x0c || t.end != e.value.len() {
        return Err(format!("extension .1.{n} is not a DER UTF8String"));
    }
    utf8(&e.value[t.body..t.end]).map(Some)
}
/// Exactly one SAN, a URI or an email; anything else (OtherName, several names) is refused.
fn san_identity(c: &ParsedCert) -> R<String> {
    let e = c.ext(OID_SAN).ok_or("no subjectAltName")?;
    let seq = tlv(&e.value, 0, e.value.len())?;
    let names = kids(&e.value, &seq)?;
    if seq.tag != 0x30 || names.len() != 1 {
        return Err("subjectAltName must hold exactly one name".into());
    }
    let n = names[0];
    if n.tag != 0x86 && n.tag != 0x81 {
        return Err("subjectAltName must be a URI or an email".into());
    }
    utf8(&e.value[n.body..n.end])
}

// ------------------------------------------------------------------------------------------------ certificates

fn validity_of(c: &Cert) -> Option<(i64, i64)> {
    match der_validity_ms(&c.raw) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => None,
    }
}
fn inside(c: &Cert, at: i64) -> bool {
    validity_of(c).map_or(false, |(a, b)| a <= at && at <= b)
}
/// `X509Certificate.checkIssued` (the name link and the key-identifier link) and `verify` (the signature under the issuer key).
fn issued_by(c: &Cert, up: &Cert) -> bool {
    c.issuer == up.subject && key_ids_match(c, up) && up.public_key().map_or(false, |k| c.verify(&k))
}
/// X509_check_issued: when `c` names an authority key id and `up` has a subject key id, they must be equal.
fn key_ids_match(c: &Cert, up: &Cert) -> bool {
    let ext = |der: &[u8], oid: &str| parse_cert(der).ok().and_then(|p| p.ext(oid).map(|e| e.value.clone()));
    let (Some(akid), Some(skid)) = (ext(&c.raw, OID_AKI), ext(&up.raw, OID_SKI)) else { return true };
    let link = || -> R<bool> {
        let seq = tlv(&akid, 0, akid.len())?;
        if seq.tag != 0x30 || seq.body >= seq.end {
            return Ok(true);
        }
        let k = tlv(&akid, seq.body, seq.end)?;
        if k.tag != 0x80 {
            return Ok(true);
        }
        let sk = tlv(&skid, 0, skid.len())?;
        Ok(sk.tag != 0x04 || akid[k.body..k.end] == skid[sk.body..sk.end])
    };
    link().unwrap_or(false)
}
/// Chain `chain` (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at `at`.
fn chain_ok(chain: &[Cert], at: i64) -> bool {
    chain.iter().enumerate().all(|(i, c)| issued_by(c, chain.get(i + 1).unwrap_or(c)) && inside(c, at) && (i == 0 || c.is_ca()))
}

// ------------------------------------------------------------------------------------------------ SCT (RFC 6962 3.2)

fn verify_sct(leaf: &ParsedCert, issuer: &Cert, roots: &PinnedRoots) -> R<Option<String>> {
    let Some(e) = leaf.ext(OID_SCT_LIST) else { return Ok(Some("no embedded SCT".into())) };
    let outer = tlv(&e.value, 0, e.value.len())?;
    if outer.tag != 0x04 {
        return Ok(Some("SCT list is not an OCTET STRING".into()));
    }
    let list = &e.value[outer.body..outer.end];
    let u16at = |b: &[u8], i: usize| -> usize { ((b[i] as usize) << 8) | b[i + 1] as usize };
    if list.len() < 2 || u16at(list, 0) != list.len() - 2 {
        return Ok(Some("SCT list length".into()));
    }
    // the precertificate TBS: the leaf TBS without the SCT list extension
    let der = &leaf.der;
    let ext_seq = kid(der, &leaf.exts_wrapper, 0)?;
    let mut kept = Vec::new();
    for k in kids(der, &ext_seq)? {
        if k.start != e.t.start {
            kept.extend_from_slice(&der[k.start..k.end]);
        }
    }
    let mut tbs_body = Vec::new();
    for k in &leaf.tbs_kids {
        if *k == leaf.exts_wrapper {
            tbs_body.extend(der_wrap(0xa3, &der_wrap(0x30, &kept)));
        } else {
            tbs_body.extend_from_slice(&der[k.start..k.end]);
        }
    }
    let tbs = der_wrap(0x30, &tbs_body);
    if tbs.len() >= 1 << 24 {
        return Ok(Some("precertificate too large".into()));
    }
    let issuer_key_hash = sha256(&issuer.spki);
    let mut why = "no SCT from a pinned CT log".to_string();
    let mut o = 2;
    while o < list.len() {
        if o + 2 > list.len() {
            return Ok(Some("SCT truncated".into()));
        }
        let n = u16at(list, o);
        let s = &list[o + 2..(o + 2 + n).min(list.len())];
        o += 2 + n;
        if s.len() != n || n < 47 {
            return Ok(Some("SCT truncated".into()));
        }
        if s[0] != 0 {
            continue;
        }
        let log_id = &s[1..33];
        let ts = u64::from_be_bytes(s[33..41].try_into().map_err(|_| "SCT truncated")?);
        let ext_len = u16at(s, 41);
        let ext = &s[43..(43 + ext_len).min(s.len())];
        let mut p = 43 + ext_len;
        if p + 4 > s.len() {
            return Ok(Some("SCT truncated".into()));
        }
        let (hash_alg, sig_alg, sig_len) = (s[p], s[p + 1], u16at(s, p + 2));
        let sig = &s[p + 4..(p + 4 + sig_len).min(s.len())];
        p += 4 + sig_len;
        if p != s.len() || sig.len() != sig_len {
            return Ok(Some("SCT malformed".into()));
        }
        let Some(log) = roots.ctlogs.iter().find(|l| l.key_id == log_id) else { continue };
        if hash_alg != 4 || (sig_alg != 3 && sig_alg != 1) {
            why = "SCT is not SHA-256 with ECDSA or RSA".into();
            continue;
        }
        if ts > i64::MAX as u64 || !log.valid.has(ts as i64) {
            why = "SCT log key not valid at its timestamp".into();
            continue;
        }
        let mut signed = vec![0u8, 0u8];
        signed.extend_from_slice(&ts.to_be_bytes());
        signed.extend_from_slice(&[0, 1]);
        signed.extend_from_slice(&issuer_key_hash);
        signed.extend_from_slice(&[(tbs.len() >> 16) as u8, (tbs.len() >> 8) as u8, tbs.len() as u8]);
        signed.extend_from_slice(&tbs);
        signed.extend_from_slice(&[(ext.len() >> 8) as u8, ext.len() as u8]);
        signed.extend_from_slice(ext);
        if verify_der_sig(&log.key, Hash::Sha256, &signed, sig) {
            return Ok(None);
        }
        why = "SCT signature invalid".into();
    }
    Ok(Some(why))
}

// ------------------------------------------------------------------------------------------------ RFC 3161 timestamps

fn digest_of(b: &[u8], t: &T) -> R<Hash> {
    match oid_text(b, &kid(b, t, 0)?)?.as_str() {
        "2.16.840.1.101.3.4.2.1" => Ok(Hash::Sha256),
        "2.16.840.1.101.3.4.2.2" => Ok(Hash::Sha384),
        "2.16.840.1.101.3.4.2.3" => Ok(Hash::Sha512),
        _ => Err("unsupported digest algorithm".into()),
    }
}
fn generalized_time(b: &[u8], t: &T) -> R<i64> {
    if t.tag != 0x18 {
        return Err("genTime is not a GeneralizedTime".into());
    }
    let s = &b[t.body..t.end];
    let bad = || "genTime malformed".to_string();
    if s.len() < 15 || s[s.len() - 1] != b'Z' || !s[..14].iter().all(u8::is_ascii_digit) {
        return Err(bad());
    }
    let frac = &s[14..s.len() - 1];
    let ms = if frac.is_empty() {
        0
    } else {
        let d = &frac[1..];
        if frac[0] != b'.' || d.is_empty() || d.len() > 9 || !d.iter().all(u8::is_ascii_digit) {
            return Err(bad());
        }
        // the reference's Math.floor(Number(`0.${frac}`) * 1000), the same binary64 operations
        (format!("0.{}", std::str::from_utf8(d).map_err(|_| bad())?).parse::<f64>().map_err(|_| bad())? * 1000.0).floor() as i64
    };
    let n = |i: usize, l: usize| s[i..i + l].iter().fold(0i64, |a, c| a * 10 + (c - b'0') as i64);
    crate::attest::util::civil_ms(n(0, 4), n(4, 2), n(6, 2), n(8, 2), n(10, 2), n(12, 2), ms).ok_or_else(bad)
}

/// Verify an RFC 3161 TimeStampResp (or bare TimeStampToken) over `data` (the raw signature bytes): CMS SignedData with
/// TSTInfo content, `messageImprint` the hash of `data`, signed attributes carrying the content type and the digest of the
/// TSTInfo, the signature over the DER SET of signed attributes under the leaf of a pinned timestamp authority whose chain (and
/// `validFor`) is valid at `genTime`, with the timeStamping EKU. Returns `genTime` (ms).
pub fn verify_rfc3161(token: &[u8], data: &[u8], tsas: &[PinnedCa]) -> Result<i64, String> {
    let mut ci = tlv(token, 0, token.len())?;
    if ci.end != token.len() || ci.tag != 0x30 {
        return Err("timestamp is not one SEQUENCE".into());
    }
    let mut parts = kids(token, &ci)?;
    let p0 = *parts.first().ok_or("timestamp empty")?;
    if p0.tag == 0x30 && p0.end - p0.body >= 3 && token[kid(token, &p0, 0)?.start] == 0x02 {
        // TimeStampResp: status (granted 0 or grantedWithMods 1), then the token
        let st = kid(token, &p0, 0)?;
        let status = &token[st.body..st.end];
        if !(status.len() == 1 && (status[0] == 0 || status[0] == 1)) {
            return Err("timestamp status is not granted".into());
        }
        ci = *parts.get(1).ok_or("no timeStampToken")?;
        parts = kids(token, &ci)?;
    }
    let (p0, p1) = (*parts.first().ok_or("not CMS SignedData")?, parts.get(1).copied());
    if oid_text(token, &p0)? != OID_SIGNED_DATA || p1.map(|p| p.tag) != Some(0xa0) {
        return Err("not CMS SignedData".into());
    }
    let sd = kid(token, &p1.unwrap(), 0)?;
    let sdk = kids(token, &sd)?;
    let encap = *sdk.iter().enumerate().find(|(i, k)| *i > 1 && k.tag == 0x30).map(|x| x.1).ok_or("no encapContentInfo")?;
    let ek = kids(token, &encap)?;
    if ek.len() < 2 || oid_text(token, &ek[0])? != OID_TST_INFO || ek[1].tag != 0xa0 {
        return Err("content is not TSTInfo".into());
    }
    let octet = kid(token, &ek[1], 0)?;
    if octet.tag != 0x04 {
        return Err("TSTInfo is not an OCTET STRING".into());
    }
    let tst_bytes = &token[octet.body..octet.end];
    let tst = tlv(tst_bytes, 0, tst_bytes.len())?;
    let tk = kids(tst_bytes, &tst)?;
    if tk.len() < 5 {
        return Err("TSTInfo truncated".into());
    }
    let mi = kids(tst_bytes, &tk[2])?;
    if mi.len() < 2 {
        return Err("messageImprint malformed".into());
    }
    let mi_alg = digest_of(tst_bytes, &mi[0])?;
    if mi_alg.digest(data) != tst_bytes[mi[1].body..mi[1].end] {
        return Err("messageImprint is not the hash of the signature".into());
    }
    let gen_time = generalized_time(tst_bytes, &tk[4])?;
    let signer_infos = *sdk.last().ok_or("no signerInfos")?;
    if signer_infos.tag != 0x31 {
        return Err("no signerInfos".into());
    }
    let sis = kids(token, &signer_infos)?;
    if sis.len() != 1 {
        return Err("exactly one SignerInfo is required".into());
    }
    let si = kids(token, &sis[0])?;
    if si.len() < 6 {
        return Err("SignerInfo truncated".into());
    }
    let d_alg = digest_of(token, &si[2])?;
    let attrs = si[3];
    if attrs.tag != 0xa0 {
        return Err("signed attributes are required".into());
    }
    let (mut ct_ok, mut md_ok) = (false, false);
    for a in kids(token, &attrs)? {
        let ak = kids(token, &a)?;
        if ak.len() < 2 {
            return Err("attribute malformed".into());
        }
        let vals = kids(token, &ak[1])?;
        let o = oid_text(token, &ak[0])?;
        if vals.len() != 1 {
            return Err("an attribute must have one value".into());
        }
        if o == OID_CONTENT_TYPE {
            ct_ok = oid_text(token, &vals[0])? == OID_TST_INFO;
        }
        if o == OID_MESSAGE_DIGEST {
            md_ok = d_alg.digest(tst_bytes) == token[vals[0].body..vals[0].end];
        }
    }
    if !ct_ok || !md_ok {
        return Err("signed attributes do not commit to the TSTInfo".into());
    }
    let mut signed_attrs = vec![0x31u8];
    signed_attrs.extend_from_slice(&token[attrs.start + 1..attrs.end]);
    let sig_t = si[5];
    if sig_t.tag != 0x04 {
        return Err("signature is not an OCTET STRING".into());
    }
    let sig = &token[sig_t.body..sig_t.end];
    for tsa in tsas {
        if !tsa.valid.has(gen_time) {
            continue;
        }
        let leaf = &tsa.chain[0];
        if !parse_cert(&leaf.raw).map_or(false, |p| p.has_eku(EKU_TIME_STAMPING)) {
            continue;
        }
        if !leaf.public_key().map_or(false, |k| verify_der_sig(&k, d_alg, &signed_attrs, sig)) {
            continue;
        }
        if !chain_ok(&tsa.chain, gen_time) {
            continue;
        }
        return Ok(gen_time);
    }
    Err("no pinned timestamp authority signed it (valid at its time)".into())
}

// ------------------------------------------------------------------------------------------------ Rekor

/// Signed-note checkpoint: origin, size and base64 root lines, a blank line, then `— <name> <base64(keyhint4 || sig)>` lines.
/// Rekor v1: ECDSA over the body, the hint the first 4 bytes of the log id. Rekor v2: the line carries the log's note name,
/// Ed25519 over the body. Witness co-signatures are ignored.
fn verify_checkpoint(text: &str, log: &PinnedLog, size: u64, root: &[u8]) -> R<Option<String>> {
    let Some(cut) = text.find("\n\n") else { return Ok(Some("checkpoint has no signature block".into())) };
    let body = &text[..cut + 1];
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() < 4 || lines[0].is_empty() {
        return Ok(Some("checkpoint body too short or without an origin".into()));
    }
    let sz = lines[1];
    if !(sz.len() > 0 && sz.as_bytes()[0] != b'0' && sz.bytes().all(|c| c.is_ascii_digit())) || sz != size.to_string() {
        return Ok(Some("checkpoint size differs from the proof".into()));
    }
    if b64_strict(lines[2]).ok_or("not base64")? != root {
        return Ok(Some("checkpoint root differs from the proof".into()));
    }
    for l in text[cut + 2..].split('\n') {
        let Some(rest) = l.strip_prefix("\u{2014} ") else { continue };
        let Some((name, sig64)) = rest.split_once(' ') else { continue };
        if name.is_empty() || name.chars().any(char::is_whitespace) || sig64.is_empty() || !sig64.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=') {
            continue;
        }
        let raw = b64_strict(sig64).ok_or("not base64")?;
        if raw.len() < 5 || raw[..4] != log.key_id[..4] {
            continue;
        }
        if log.v2_name.as_deref().is_some_and(|n| n != name) {
            continue;
        }
        let ok = match (&log.key, &log.v2_name) {
            (PubKey::Ed25519(k), Some(_)) => ed25519_ok(k, body.as_bytes(), &raw[4..]),
            (k, None) => verify_der_sig(k, Hash::Sha256, body.as_bytes(), &raw[4..]),
            _ => false,
        };
        if ok {
            return Ok(None);
        }
    }
    Ok(Some("no checkpoint signature by the pinned log key".into()))
}

fn ed25519_ok(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (<[u8; 32]>::try_from(key), <[u8; 64]>::try_from(sig)) else { return false };
    ed25519_dalek::VerifyingKey::from_bytes(&k).map_or(false, |vk| vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&s)).is_ok())
}

fn dec_int(v: Option<&Value>) -> R<u64> {
    let s = v.and_then(Value::as_str).ok_or("not a decimal integer string")?;
    if s.is_empty() || s.len() > 16 || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err("not a decimal integer string".into());
    }
    let n: u64 = s.parse().map_err(|_| "not a decimal integer string")?;
    if n > 9_007_199_254_740_991 {
        return Err("integer out of range".into());
    }
    Ok(n)
}

/// DSSE PAE (secure-systems-lab/dsse protocol.md).
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    m.extend_from_slice(payload);
    m
}

fn leaf_hash_alg(k: &PubKey) -> Option<Hash> {
    match k {
        PubKey::Ec { curve: EcCurve::P256, .. } => Some(Hash::Sha256),
        PubKey::Ec { curve: EcCurve::P384, .. } => Some(Hash::Sha384),
        _ => None,
    }
}

fn pem_der(pem: &str) -> R<Vec<u8>> {
    let m = pem.strip_prefix("-----BEGIN CERTIFICATE-----\n").and_then(|r| r.strip_suffix('\n').unwrap_or(r).strip_suffix("-----END CERTIFICATE-----"));
    match m {
        Some(mid) if !mid.is_empty() && mid.bytes().all(|c| c.is_ascii_alphanumeric() || b"+/=\n".contains(&c)) => b64_strict(&mid.replace('\n', "")).ok_or_else(|| "not base64".into()),
        _ => Ok(Vec::new()),
    }
}

// ------------------------------------------------------------------------------------------------ the verifier

/// What a verified bundle establishes, before any SLSA reading: the `core` object of sigstore-vectors.json (a JSON object
/// with `identity`, `oidc_issuer`, `source_*` when present, `predicate_type`, `subjects`, `signed_time`, `rekor_log_index`,
/// `rekor`, `timestamps`), and the parsed Statement.
#[derive(Clone, Debug)]
pub struct SigstoreCore {
    pub core: Value,
    pub statement: Value,
}

/// A refusal: the reference's `code` and a detail.
#[derive(Clone, Debug, PartialEq)]
pub struct SigstoreError {
    pub code: &'static str,
    pub detail: String,
}

/// Verify a Sigstore bundle carrying a DSSE in-toto statement against pinned roots. Never panics; every refusal has a code.
pub fn verify_sigstore_bundle_core(bundle: &Value, roots: &PinnedRoots) -> Result<SigstoreCore, SigstoreError> {
    let mut stage = "malformed";
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core(bundle, roots, &mut stage))) {
        Ok(Ok(Ok(c))) => Ok(c),
        Ok(Ok(Err((code, detail)))) => Err(SigstoreError { code, detail }),
        Ok(Err(e)) => Err(SigstoreError { code: stage, detail: format!("fail closed: {e}") }),
        Err(_) => Err(SigstoreError { code: stage, detail: "fail closed: panic".into() }),
    }
}

type Refusal = (&'static str, String);

fn core(bundle: &Value, o: &PinnedRoots, stage: &mut &'static str) -> R<Result<SigstoreCore, Refusal>> {
    macro_rules! no {
        ($c:expr, $d:expr) => {
            return Ok(Err(($c, String::from($d))))
        };
    }
    let (Some(b), Some(vm)) = (bundle.as_object(), obj(bundle.get("verificationMaterial"))) else { no!("malformed", "not a bundle") };
    let mt = b.get("mediaType").and_then(Value::as_str).unwrap_or("");
    if !SIGSTORE_BUNDLE_MEDIA_TYPES.contains(&mt) {
        no!("media_type", format!("unsupported media type {mt}"));
    }
    let v03 = mt != SIGSTORE_BUNDLE_MEDIA_TYPES[0];
    let cert_raw = if v03 {
        obj(vm.get("certificate")).and_then(|c| c.get("rawBytes"))
    } else {
        obj(vm.get("x509CertificateChain")).and_then(|c| c.get("certificates")).and_then(Value::as_array).and_then(|a| obj(a.first())).and_then(|c| c.get("rawBytes"))
    };
    let Some(cert_raw) = cert_raw else { no!("not_keyless", "no Fulcio certificate (public-key bundles are not supported)") };
    let Some(env) = obj(b.get("dsseEnvelope")).filter(|_| !b.contains_key("messageSignature")) else { no!("envelope", "not a DSSE bundle") };
    if env.get("payloadType").and_then(Value::as_str) != Some(INTOTO_PAYLOAD_TYPE) {
        no!("envelope", "payloadType is not application/vnd.in-toto+json");
    }
    let sigs = env.get("signatures").and_then(Value::as_array);
    let Some(sig0) = sigs.filter(|s| s.len() == 1).and_then(|s| s[0].as_object()) else { no!("envelope", "a DSSE envelope must carry exactly one signature") };
    let payload = b64(env.get("payload"))?;
    let dsse_sig = b64(sig0.get("sig"))?;
    let pae = dsse_pae(INTOTO_PAYLOAD_TYPE, &payload);
    *stage = "cert_parse";
    let leaf_der = b64(Some(cert_raw))?;
    let leaf = full_cert(&leaf_der)?;
    let pc = parse_cert(&leaf_der)?;
    let leaf_key = leaf.public_key()?;
    let alg = leaf_hash_alg(&leaf_key);

    // ---- the log entry and its log
    *stage = "tlog_count";
    let Some(t) = vm.get("tlogEntries").and_then(Value::as_array).filter(|a| a.len() == 1).and_then(|a| a[0].as_object()) else {
        no!("tlog_count", "exactly one transparency log entry is required")
    };
    *stage = "tlog_kind";
    let kv = obj(t.get("kindVersion")).map(|k| format!("{}/{}", js_string(k.get("kind")), js_string(k.get("version")))).unwrap_or_default();
    if !["dsse/0.0.1", "intoto/0.0.2", "hashedrekord/0.0.2"].contains(&kv.as_str()) {
        no!("tlog_kind", format!("unsupported entry {kv}"));
    }
    let v2 = kv == "hashedrekord/0.0.2";
    *stage = "tlog_key";
    let key_id = b64(obj(t.get("logId")).and_then(|l| l.get("keyId")))?;
    let Some(log) = o.tlogs.iter().find(|l| l.key_id == key_id) else { no!("tlog_key", "the entry names a log the verifier did not pin") };
    if v2 != log.v2_name.is_some() {
        no!("tlog_key", "the entry type does not match the log version");
    }
    let log_index = dec_int(t.get("logIndex"))?;
    let body = b64(t.get("canonicalizedBody"))?;

    // ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
    *stage = "tsa";
    let mut times: Vec<i64> = Vec::new();
    let tvd = obj(vm.get("timestampVerificationData"));
    for ts in tvd.and_then(|t| t.get("rfc3161Timestamps")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]) {
        times.push(verify_rfc3161(&b64(ts.get("signedTimestamp"))?, &dsse_sig, &o.tsas)?);
    }
    let tsa_count = times.len();
    let mut set = false;
    if let (false, Some(ip)) = (v2, obj(t.get("inclusionPromise"))) {
        *stage = "tlog_set";
        let integrated = dec_int(t.get("integratedTime"))?;
        let body_json = serde_json::to_string(t.get("canonicalizedBody").unwrap_or(&Value::Null)).map_err(|e| e.to_string())?;
        let msg = format!("{{\"body\":{body_json},\"integratedTime\":{integrated},\"logID\":\"{}\",\"logIndex\":{log_index}}}", crate::attest::util::hex_lower(&key_id));
        if !verify_der_sig(&log.key, Hash::Sha256, msg.as_bytes(), &b64(ip.get("signedEntryTimestamp"))?) {
            no!("tlog_set", "signed entry timestamp invalid");
        }
        times.push(integrated as i64 * 1000);
        set = true;
    }
    if times.is_empty() {
        no!("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp");
    }
    if times.iter().any(|at| !log.valid.has(*at)) {
        no!("tlog_key", "the log key was not valid at a signing time");
    }

    // ---- inclusion
    *stage = "tlog_inclusion";
    let ip = obj(t.get("inclusionProof"));
    let (Some(ip), Some(hashes)) = (ip, ip.and_then(|i| i.get("hashes")).and_then(Value::as_array)) else { no!("tlog_inclusion", "no inclusion proof") };
    let Some(cp) = obj(ip.get("checkpoint")) else { no!("tlog_inclusion", "no inclusion proof") };
    let root = b64(ip.get("rootHash"))?;
    let size = dec_int(ip.get("treeSize"))?;
    let proof = hashes.iter().map(|h| b64(Some(h))).collect::<R<Vec<_>>>()?;
    if !verify_rfc9162_inclusion(&rfc9162_leaf_hash(&body), dec_int(ip.get("logIndex"))?, size, &proof, &root) {
        no!("tlog_inclusion", "the inclusion proof does not lead to the root");
    }
    *stage = "tlog_checkpoint";
    if let Some(e) = verify_checkpoint(&js_string(cp.get("envelope")), log, size, &root)? {
        no!("tlog_checkpoint", e);
    }

    // ---- certificate path at every verified time (hybrid model), CT
    *stage = "cert_chain";
    let issuer = o.cas.iter().find(|ca| {
        times.iter().all(|at| ca.valid.has(*at)) && issued_by(&leaf, &ca.chain[0]) && times.iter().all(|at| chain_ok(&ca.chain, *at)) && ca.chain.iter().all(Cert::is_ca)
    });
    let Some(issuer) = issuer.map(|ca| &ca.chain[0]) else { no!("cert_chain", "no pinned CA issued the certificate, valid at every signing time") };
    if leaf.is_ca() {
        no!("cert_chain", "the leaf is a CA certificate");
    }
    if !times.iter().all(|at| inside(&leaf, *at)) {
        no!("cert_time", "the certificate was not valid at a signing time");
    }
    if !pc.has_eku(EKU_CODE_SIGNING) {
        no!("cert_eku", "the certificate lacks the code-signing EKU");
    }
    if !o.ctlogs.is_empty() {
        *stage = "sct";
        if let Some(e) = verify_sct(&pc, issuer, o)? {
            no!("sct", e);
        }
    }

    // ---- the entry body names this envelope
    *stage = "tlog_body";
    let eb: Value = serde_json::from_str(&String::from_utf8_lossy(&body)).map_err(|e| e.to_string())?;
    let empty = Map::new();
    let spec = obj(eb.get("spec")).unwrap_or(&empty);
    if format!("{}/{}", js_string(eb.get("kind")), js_string(eb.get("apiVersion"))) != kv {
        no!("tlog_body", "the entry body is not the kind the bundle names");
    }
    let payload_sha = crate::attest::util::hex_lower(&sha256(&payload));
    let ph_ok = |ph: Option<&Map<String, Value>>| ph.map_or(false, |p| p.get("algorithm").and_then(Value::as_str) == Some("sha256") && p.get("value").and_then(Value::as_str) == Some(payload_sha.as_str()));
    fn one_sig(v: Option<&Value>) -> Option<&Map<String, Value>> {
        v.and_then(Value::as_array).filter(|a| a.len() == 1).and_then(|a| a[0].as_object())
    }
    let pem_of = |v: Option<&Value>| -> R<Vec<u8>> { pem_der(&String::from_utf8_lossy(&b64(v)?)) };
    if kv == "dsse/0.0.1" {
        if !ph_ok(obj(spec.get("payloadHash"))) {
            no!("tlog_body", "the entry names another payload");
        }
        let Some(s) = one_sig(spec.get("signatures")) else { no!("tlog_body", "the entry must name exactly one signature") };
        if b64(s.get("signature"))? != dsse_sig {
            no!("tlog_body", "the entry names another signature");
        }
        if pem_of(s.get("verifier"))? != leaf_der {
            no!("tlog_body", "the entry names another certificate");
        }
    } else if kv == "intoto/0.0.2" {
        // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
        let c = obj(spec.get("content")).unwrap_or(&empty);
        if !ph_ok(obj(c.get("payloadHash"))) {
            no!("tlog_body", "the entry names another payload");
        }
        let Some(s) = one_sig(obj(c.get("envelope")).and_then(|e| e.get("signatures"))) else { no!("tlog_body", "the entry must name exactly one signature") };
        let inner: String = b64(s.get("sig"))?.iter().map(|&c| c as char).collect();
        if b64(Some(&Value::String(inner)))? != dsse_sig {
            no!("tlog_body", "the entry names another signature");
        }
        if pem_of(s.get("publicKey"))? != leaf_der {
            no!("tlog_body", "the entry names another certificate");
        }
    } else {
        // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
        let h = obj(spec.get("hashedRekordV002")).unwrap_or(&empty);
        let data = obj(h.get("data")).unwrap_or(&empty);
        let hash = match data.get("algorithm").and_then(Value::as_str) {
            Some("SHA2_256") => Some(Hash::Sha256),
            Some("SHA2_384") => Some(Hash::Sha384),
            Some("SHA2_512") => Some(Hash::Sha512),
            _ => None,
        };
        let Some(hash) = hash.filter(|h| Some(*h) == alg) else { no!("tlog_body", "the entry digest algorithm is not the signing key's") };
        if b64(data.get("digest"))? != hash.digest(&pae) {
            no!("tlog_body", "the entry names another envelope");
        }
        let sg = obj(h.get("signature")).unwrap_or(&empty);
        if b64(sg.get("content"))? != dsse_sig {
            no!("tlog_body", "the entry names another signature");
        }
        if b64(obj(sg.get("verifier")).and_then(|v| obj(v.get("x509Certificate"))).and_then(|x| x.get("rawBytes")))? != leaf_der {
            no!("tlog_body", "the entry names another certificate");
        }
    }

    // ---- DSSE signature
    *stage = "signature";
    let Some(alg) = alg else { no!("signature", "unsupported leaf key type") };
    if !verify_der_sig(&leaf_key, alg, &pae, &dsse_sig) {
        no!("signature", "DSSE signature invalid");
    }

    // ---- identity
    *stage = "identity";
    let identity = san_identity(&pc)?;
    let (iss_v2, iss_v1) = (fulcio_ext(&pc, 8)?, fulcio_ext(&pc, 1)?);
    if let (Some(a), Some(b)) = (&iss_v2, &iss_v1) {
        if a != b {
            no!("identity", "the two issuer extensions disagree");
        }
    }
    let Some(oidc_issuer) = iss_v2.or(iss_v1).filter(|s| !s.is_empty()) else { no!("identity", "no OIDC issuer extension") };
    let (source_repo, source_digest, source_ref) = (fulcio_ext(&pc, 12)?, fulcio_ext(&pc, 13)?, fulcio_ext(&pc, 14)?);

    // ---- statement
    *stage = "statement";
    let st: Value = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
    if st.get("_type").and_then(Value::as_str) != Some(INTOTO_STATEMENT_V1) {
        no!("statement", "not an in-toto Statement v1");
    }
    let Some(subs) = st.get("subject").and_then(Value::as_array).filter(|a| !a.is_empty()) else { no!("statement", "no subject") };
    let mut subjects = Vec::new();
    for s in subs {
        let d = s.get("digest").and_then(Value::as_object);
        for a in ["sha256", "sha512"] {
            if let Some(v) = d.and_then(|d| d.get(a)).and_then(Value::as_str) {
                subjects.push(json!({ "alg": a, "digest": v }));
            }
        }
    }
    if subjects.is_empty() || subjects.len() > 64 {
        no!("statement", "no sha256/sha512 subject digest (or more than 64)");
    }
    let Some(pt) = st.get("predicateType").and_then(Value::as_str) else { no!("statement", "no predicateType") };
    let mut c = Map::new();
    c.insert("identity".into(), json!(identity));
    c.insert("oidc_issuer".into(), json!(oidc_issuer));
    for (k, v) in [("source_repo", source_repo), ("source_ref", source_ref), ("source_digest", source_digest)] {
        if let Some(v) = v {
            c.insert(k.into(), json!(v));
        }
    }
    c.insert("predicate_type".into(), json!(pt));
    c.insert("subjects".into(), Value::Array(subjects));
    c.insert("signed_time".into(), json!(times.iter().min().copied().unwrap_or(0).div_euclid(1000)));
    c.insert("rekor_log_index".into(), json!(log_index));
    c.insert("rekor".into(), json!(if v2 { "v2" } else { "v1" }));
    c.insert("timestamps".into(), json!({ "tsa": tsa_count, "set": set }));
    Ok(Ok(SigstoreCore { core: Value::Object(c), statement: st }))
}

/// `String(v)` for the members the reference interpolates (a string as is; anything else its JSON text, `undefined` absent).
fn js_string(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(x) => x.to_string(),
        None => "undefined".into(),
    }
}

/// [`verify_sigstore_bundle_core`], then the SLSA v1 predicate: the `facts` member of a [`crate::provenance_gate`] input.
pub fn verify_sigstore_bundle(bundle: &Value, roots: &PinnedRoots) -> Result<Value, SigstoreError> {
    let r = verify_sigstore_bundle_core(bundle, roots)?;
    let (st, c) = (&r.statement, &r.core);
    let pred = |d: &str| Err(SigstoreError { code: "predicate", detail: d.to_string() });
    if st.get("predicateType").and_then(Value::as_str) != Some(SLSA_PROVENANCE_V1) {
        return pred("predicate is not SLSA provenance v1");
    }
    let empty = Map::new();
    let pr = obj(st.get("predicate")).unwrap_or(&empty);
    let bd = obj(pr.get("buildDefinition")).unwrap_or(&empty);
    let rd = obj(pr.get("runDetails")).unwrap_or(&empty);
    let builder_id = obj(rd.get("builder")).and_then(|b| b.get("id")).and_then(Value::as_str);
    let (Some(build_type), Some(builder_id), Some(_)) = (bd.get("buildType").and_then(Value::as_str), builder_id, obj(bd.get("externalParameters"))) else {
        return pred("buildType, externalParameters and builder.id are required (SLSA Build L1)");
    };
    let mut f = Map::new();
    f.insert("v".into(), json!(1));
    f.insert("predicate_type".into(), json!(SLSA_PROVENANCE_V1));
    f.insert("build_type".into(), json!(build_type));
    f.insert("builder_id".into(), json!(builder_id));
    f.insert("subjects".into(), c["subjects"].clone());
    f.insert("identity".into(), c["identity"].clone());
    f.insert("oidc_issuer".into(), c["oidc_issuer"].clone());
    for k in ["source_repo", "source_ref", "source_digest"] {
        if let Some(v) = c.get(k) {
            f.insert(k.into(), v.clone());
        }
    }
    if let Some(dep0) = bd.get("resolvedDependencies").and_then(Value::as_array).and_then(|a| obj(a.first())) {
        if let Some(uri) = dep0.get("uri").and_then(Value::as_str) {
            let mut ps = Map::new();
            ps.insert("uri".into(), json!(uri));
            if let Some(g) = obj(dep0.get("digest")).and_then(|d| d.get("gitCommit")).and_then(Value::as_str) {
                ps.insert("git_commit".into(), json!(g));
            }
            f.insert("provenance_source".into(), Value::Object(ps));
        }
    }
    f.insert("integrated_time".into(), c["signed_time"].clone());
    f.insert("rekor_log_index".into(), c["rekor_log_index"].clone());
    Ok(Value::Object(f))
}
