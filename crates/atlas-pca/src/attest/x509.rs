//! A small X.509 reader (the role OpenSSL's `X509Certificate` plays for the TypeScript verifiers): structure, names,
//! public keys and signature verification (ECDSA P-256 / P-384, RSA PKCS#1 v1.5 and RSASSA-PSS), PEM handling.

use super::der::{read_cert_role_info, tlv_at, Tlv};
use super::util::{b64_strict, sha1, sha256, sha384, sha512};
use p256::ecdsa::signature::hazmat::PrehashVerifier;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn digest(&self, m: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => sha1(m),
            Hash::Sha256 => sha256(m),
            Hash::Sha384 => sha384(m),
            Hash::Sha512 => sha512(m),
        }
    }
    /// DER `DigestInfo` prefix (RFC 8017 9.2 note 1).
    fn prefix(&self) -> &'static [u8] {
        match self {
            Hash::Sha1 => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14],
            Hash::Sha256 => &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            Hash::Sha384 => &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            Hash::Sha512 => &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    Other,
}

impl EcCurve {
    pub fn coord_len(&self) -> usize {
        match self {
            EcCurve::P256 => 32,
            EcCurve::P384 => 48,
            EcCurve::P521 => 66,
            EcCurve::Other => 0,
        }
    }
    /// Node's `namedCurve`.
    pub fn node_name(&self) -> Option<&'static str> {
        match self {
            EcCurve::P256 => Some("prime256v1"),
            EcCurve::P384 => Some("secp384r1"),
            EcCurve::P521 => Some("secp521r1"),
            EcCurve::Other => None,
        }
    }
    /// JWK `crv`.
    pub fn jwk_name(&self) -> Option<&'static str> {
        match self {
            EcCurve::P256 => Some("P-256"),
            EcCurve::P384 => Some("P-384"),
            EcCurve::P521 => Some("P-521"),
            EcCurve::Other => None,
        }
    }
    fn oid_der(&self) -> &'static [u8] {
        match self {
            EcCurve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            EcCurve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            _ => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
        }
    }
}

/// A public key as far as the verifiers need it.
#[derive(Clone, Debug)]
pub enum PubKey {
    /// `point` is the uncompressed SEC1 encoding.
    Ec { curve: EcCurve, point: Vec<u8> },
    /// Big-endian modulus and exponent without leading zeros.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ed25519(Vec<u8>),
    Unknown(Vec<u8>),
}

pub fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else if n < 0x10000 {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else {
        out.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}

fn der_uint(be: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
    if v.is_empty() {
        v.push(0);
    }
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    der_wrap(0x02, &v)
}

fn strip_zeros(b: &[u8]) -> Vec<u8> {
    b.iter().copied().skip_while(|x| *x == 0).collect()
}

impl PubKey {
    /// Node's `asymmetricKeyType`.
    pub fn type_name(&self) -> &'static str {
        match self {
            PubKey::Ec { .. } => "ec",
            PubKey::Rsa { .. } => "rsa",
            PubKey::Ed25519(_) => "ed25519",
            PubKey::Unknown(_) => "unknown",
        }
    }
    /// JWK `kty` of the key export.
    pub fn jwk_kty(&self) -> &'static str {
        match self {
            PubKey::Ec { .. } => "EC",
            PubKey::Rsa { .. } => "RSA",
            PubKey::Ed25519(_) => "OKP",
            PubKey::Unknown(_) => "undefined",
        }
    }
    /// JWK `crv` of the key export (`undefined` when absent).
    pub fn jwk_crv(&self) -> String {
        match self {
            PubKey::Ec { curve, .. } => curve.jwk_name().unwrap_or("undefined").to_string(),
            PubKey::Ed25519(_) => "Ed25519".to_string(),
            _ => "undefined".to_string(),
        }
    }
    /// The canonical SubjectPublicKeyInfo DER (what `publicKey.export({type:'spki',format:'der'})` returns).
    pub fn spki_der(&self) -> Vec<u8> {
        match self {
            PubKey::Ec { curve, point } if *curve != EcCurve::Other => {
                let mut alg = vec![0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
                alg.extend_from_slice(curve.oid_der());
                let mut bits = vec![0u8];
                bits.extend_from_slice(point);
                let mut body = der_wrap(0x30, &alg);
                body.extend_from_slice(&der_wrap(0x03, &bits));
                der_wrap(0x30, &body)
            }
            PubKey::Rsa { n, e } => {
                let alg = vec![0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
                let mut inner = der_uint(n);
                inner.extend_from_slice(&der_uint(e));
                let mut bits = vec![0u8];
                bits.extend_from_slice(&der_wrap(0x30, &inner));
                let mut body = der_wrap(0x30, &alg);
                body.extend_from_slice(&der_wrap(0x03, &bits));
                der_wrap(0x30, &body)
            }
            PubKey::Ed25519(k) => {
                let mut bits = vec![0u8];
                bits.extend_from_slice(k);
                let mut body = der_wrap(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);
                body.extend_from_slice(&der_wrap(0x03, &bits));
                der_wrap(0x30, &body)
            }
            PubKey::Ec { .. } => Vec::new(),
            PubKey::Unknown(raw) => raw.clone(),
        }
    }
    /// SHA-256 of the canonical SPKI, lowercase hex (the pin format).
    pub fn spki_sha256_hex(&self) -> String {
        super::util::hex_lower(&sha256(&self.spki_der()))
    }
    pub fn spki_sha384_hex(&self) -> String {
        super::util::hex_lower(&sha384(&self.spki_der()))
    }
}

fn curve_of_oid(oid: &[u8]) -> EcCurve {
    match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => EcCurve::P256,
        [0x2b, 0x81, 0x04, 0x00, 0x22] => EcCurve::P384,
        [0x2b, 0x81, 0x04, 0x00, 0x23] => EcCurve::P521,
        _ => EcCurve::Other,
    }
}

fn tlv_in(b: &[u8], off: usize, limit: usize) -> Result<Tlv, String> {
    match tlv_at(b, off) {
        Ok(t) if t.end <= limit => Ok(t),
        _ => Err("error:068000A8:asn1 encoding routines::wrong tag".to_string()),
    }
}

/// Parse a SubjectPublicKeyInfo (the whole TLV).
pub fn parse_spki(spki: &[u8]) -> Result<PubKey, String> {
    let bad = || "error:1E08010C:DECODER routines::unsupported".to_string();
    let outer = tlv_in(spki, 0, spki.len())?;
    if outer.tag != 0x30 || outer.end != spki.len() {
        return Err(bad());
    }
    let alg = tlv_in(spki, outer.start, outer.end)?;
    if alg.tag != 0x30 {
        return Err(bad());
    }
    let bits = tlv_in(spki, alg.end, outer.end)?;
    if bits.tag != 0x03 || bits.end != outer.end || bits.end <= bits.start || spki[bits.start] != 0 {
        return Err(bad());
    }
    let key = &spki[bits.start + 1..bits.end];
    let oid = tlv_in(spki, alg.start, alg.end)?;
    if oid.tag != 0x06 {
        return Err(bad());
    }
    let oid_bytes = &spki[oid.start..oid.end];
    match oid_bytes {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => {
            let params = tlv_in(spki, oid.end, alg.end)?;
            if params.tag != 0x06 || params.end != alg.end {
                return Err(bad());
            }
            let curve = curve_of_oid(&spki[params.start..params.end]);
            if curve == EcCurve::Other || key.len() != 1 + 2 * curve.coord_len() || key[0] != 0x04 {
                return Ok(PubKey::Unknown(spki.to_vec()));
            }
            Ok(PubKey::Ec { curve, point: key.to_vec() })
        }
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => {
            let seq = tlv_in(key, 0, key.len())?;
            if seq.tag != 0x30 || seq.end != key.len() {
                return Err(bad());
            }
            let n = tlv_in(key, seq.start, seq.end)?;
            let e = tlv_in(key, n.end, seq.end)?;
            if n.tag != 0x02 || e.tag != 0x02 || e.end != seq.end {
                return Err(bad());
            }
            Ok(PubKey::Rsa { n: strip_zeros(&key[n.start..n.end]), e: strip_zeros(&key[e.start..e.end]) })
        }
        [0x2b, 0x65, 0x70] => Ok(PubKey::Ed25519(key.to_vec())),
        _ => Ok(PubKey::Unknown(spki.to_vec())),
    }
}

// ───────────────────────────── signature primitives

/// ECDSA over a prehashed digest; `rs` is the fixed-width big-endian `r || s`.
pub fn ecdsa_verify_raw(curve: EcCurve, point: &[u8], digest: &[u8], rs: &[u8]) -> bool {
    match curve {
        EcCurve::P256 => {
            let vk = match p256::ecdsa::VerifyingKey::from_sec1_bytes(point) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let sig = match p256::ecdsa::Signature::from_slice(rs) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify_prehash(digest, &sig).is_ok()
        }
        EcCurve::P384 => {
            let vk = match p384::ecdsa::VerifyingKey::from_sec1_bytes(point) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let sig = match p384::ecdsa::Signature::from_slice(rs) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.verify_prehash(digest, &sig).is_ok()
        }
        _ => false,
    }
}

/// `ECDSA-Sig-Value` (DER) to fixed-width `r || s`; strict DER, positive minimal integers.
pub fn ecdsa_der_to_raw(der: &[u8], coord: usize) -> Option<Vec<u8>> {
    let seq = tlv_at(der, 0).ok()?;
    if seq.tag != 0x30 || seq.end != der.len() {
        return None;
    }
    let r = tlv_at(der, seq.start).ok()?;
    let s = tlv_at(der, r.end).ok()?;
    if r.tag != 0x02 || s.tag != 0x02 || s.end != seq.end || r.end > seq.end {
        return None;
    }
    let mut out = vec![0u8; coord * 2];
    for (t, base) in [(r, 0usize), (s, coord)] {
        let v = &der[t.start..t.end];
        if v.is_empty() || v[0] & 0x80 != 0 || (v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0) {
            return None;
        }
        let v = if v[0] == 0 { &v[1..] } else { v };
        if v.len() > coord {
            return None;
        }
        out[base + coord - v.len()..base + coord].copy_from_slice(v);
    }
    Some(out)
}

fn rsa_key(n: &[u8], e: &[u8]) -> Option<rsa::RsaPublicKey> {
    rsa::RsaPublicKey::new_with_max_size(rsa::BigUint::from_bytes_be(n), rsa::BigUint::from_bytes_be(e), 16384).ok()
}

pub fn rsa_pkcs1_verify(n: &[u8], e: &[u8], hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    let key = match rsa_key(n, e) {
        Some(k) => k,
        None => return false,
    };
    let mut hashed = hash.prefix().to_vec();
    hashed.extend_from_slice(&hash.digest(msg));
    key.verify(rsa::Pkcs1v15Sign::new_unprefixed(), &hashed, sig).is_ok()
}

pub fn rsa_pss_verify(n: &[u8], e: &[u8], hash: Hash, salt_len: usize, msg: &[u8], sig: &[u8]) -> bool {
    let key = match rsa_key(n, e) {
        Some(k) => k,
        None => return false,
    };
    let digest = hash.digest(msg);
    let scheme = match hash {
        Hash::Sha256 => rsa::Pss::new_with_salt::<sha2::Sha256>(salt_len),
        Hash::Sha384 => rsa::Pss::new_with_salt::<sha2::Sha384>(salt_len),
        Hash::Sha512 => rsa::Pss::new_with_salt::<sha2::Sha512>(salt_len),
        Hash::Sha1 => return false,
    };
    key.verify(scheme, &digest, sig).is_ok()
}

/// Node's `crypto.verify(hash, data, key, sig)` with the default (DER) signature encoding: ECDSA keys take a DER
/// signature, RSA keys PKCS#1 v1.5.
pub fn verify_der_sig(key: &PubKey, hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    match key {
        PubKey::Ec { curve, point } => match ecdsa_der_to_raw(sig, curve.coord_len()) {
            Some(rs) => ecdsa_verify_raw(*curve, point, &hash.digest(msg), &rs),
            None => false,
        },
        PubKey::Rsa { n, e } => rsa_pkcs1_verify(n, e, hash, msg, sig),
        _ => false,
    }
}

/// `crypto.verify(hash, data, {key, dsaEncoding: 'ieee-p1363'}, sig)`: ECDSA keys take the raw `r || s`.
pub fn verify_p1363_sig(key: &PubKey, hash: Hash, msg: &[u8], sig: &[u8]) -> bool {
    match key {
        PubKey::Ec { curve, point } => ecdsa_verify_raw(*curve, point, &hash.digest(msg), sig),
        PubKey::Rsa { n, e } => rsa_pkcs1_verify(n, e, hash, msg, sig),
        _ => false,
    }
}

// ───────────────────────────── certificates

#[derive(Clone, Debug)]
pub struct Cert {
    /// The certificate TLV exactly (bytes after it are not part of it).
    pub raw: Vec<u8>,
    /// The tbsCertificate TLV.
    pub tbs: Vec<u8>,
    /// Serial number INTEGER content.
    pub serial: Vec<u8>,
    pub tbs_sig_alg: Vec<u8>,
    pub sig_alg: Vec<u8>,
    sig_unused: u8,
    pub sig: Vec<u8>,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
}

fn asn1_err() -> String {
    "error:068000A8:asn1 encoding routines::wrong tag".to_string()
}

fn expect(b: &[u8], off: usize, limit: usize, tag: u8) -> Result<Tlv, String> {
    let t = tlv_in(b, off, limit)?;
    if t.tag != tag {
        return Err(asn1_err());
    }
    Ok(t)
}

impl Cert {
    /// Parse one DER certificate. Like OpenSSL, bytes after the certificate are ignored.
    pub fn from_der(der: &[u8]) -> Result<Cert, String> {
        let outer = expect(der, 0, der.len(), 0x30)?;
        let tbs = expect(der, outer.start, outer.end, 0x30)?;
        let sig_alg = expect(der, tbs.end, outer.end, 0x30)?;
        let sig = expect(der, sig_alg.end, outer.end, 0x03)?;
        if sig.end != outer.end || sig.end <= sig.start {
            return Err(asn1_err());
        }
        let mut el = tlv_in(der, tbs.start, tbs.end)?;
        if el.tag == 0xa0 {
            el = tlv_in(der, el.end, tbs.end)?;
        }
        if el.tag != 0x02 {
            return Err(asn1_err());
        }
        let serial = der[el.start..el.end].to_vec();
        let tbs_alg = expect(der, el.end, tbs.end, 0x30)?;
        let issuer = expect(der, tbs_alg.end, tbs.end, 0x30)?;
        let validity = expect(der, issuer.end, tbs.end, 0x30)?;
        let nb = tlv_in(der, validity.start, validity.end)?;
        let na = tlv_in(der, nb.end, validity.end)?;
        if (nb.tag != 0x17 && nb.tag != 0x18) || (na.tag != 0x17 && na.tag != 0x18) || na.end != validity.end {
            return Err(asn1_err());
        }
        let subject = expect(der, validity.end, tbs.end, 0x30)?;
        let spki = expect(der, subject.end, tbs.end, 0x30)?;
        let mut p = spki.end;
        while p < tbs.end {
            let t = tlv_in(der, p, tbs.end)?;
            if t.tag != 0x81 && t.tag != 0x82 && t.tag != 0xa3 {
                return Err(asn1_err());
            }
            p = t.end;
        }
        let full = |off: usize, t: &Tlv| -> Vec<u8> { der[off..t.end].to_vec() };
        Ok(Cert {
            raw: der[..outer.end].to_vec(),
            tbs: full(outer.start, &tbs),
            serial,
            tbs_sig_alg: full(el.end, &tbs_alg),
            sig_alg: full(tbs.end, &sig_alg),
            sig_unused: der[sig.start],
            sig: der[sig.start + 1..sig.end].to_vec(),
            issuer: full(tbs_alg.end, &issuer),
            subject: full(validity.end, &subject),
            spki: full(subject.end, &spki),
        })
    }

    /// Parse one PEM `CERTIFICATE` block (header and footer included). Unlike a bare DER buffer, a PEM payload must be exactly
    /// one certificate: OpenSSL reads it as a certificate with trust data, so bytes after the certificate are an error.
    pub fn from_pem(block: &str) -> Result<Cert, String> {
        let der = pem_to_der(block)?;
        let cert = Cert::from_der(&der)?;
        if cert.raw.len() != der.len() {
            return Err("error:0688010A:asn1 encoding routines::nested asn1 error".to_string());
        }
        Ok(cert)
    }

    pub fn public_key(&self) -> Result<PubKey, String> {
        parse_spki(&self.spki)
    }

    /// Node's `subject` / `issuer` rendering.
    pub fn subject_string(&self) -> String {
        name_to_string(&self.subject)
    }
    pub fn issuer_string(&self) -> String {
        name_to_string(&self.issuer)
    }

    /// Node's `serialNumber`: uppercase hex.
    pub fn serial_hex(&self) -> String {
        super::util::hex_lower(&self.serial).to_uppercase()
    }

    /// Node's `ca` (`X509_check_ca() == 1`).
    pub fn is_ca(&self) -> bool {
        match read_cert_role_info(&self.raw) {
            Ok(i) => i.has_basic_constraints && i.ca && (!i.has_key_usage || i.key_cert_sign),
            Err(_) => false,
        }
    }

    /// Node's `X509Certificate.verify(publicKey)`.
    pub fn verify(&self, key: &PubKey) -> bool {
        if self.sig_alg != self.tbs_sig_alg || self.sig_unused != 0 {
            return false;
        }
        let alg = match tlv_at(&self.sig_alg, 0) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let oid = match tlv_at(&self.sig_alg, alg.start) {
            Ok(t) if t.tag == 0x06 => t,
            _ => return false,
        };
        let oid_bytes = self.sig_alg[oid.start..oid.end].to_vec();
        const ECDSA: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];
        const PKCS1: [u8; 8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
        let tbs = &self.tbs;
        if oid_bytes.len() == 8 && oid_bytes[..7] == ECDSA {
            let hash = match oid_bytes[7] {
                2 => Hash::Sha256,
                3 => Hash::Sha384,
                4 => Hash::Sha512,
                _ => return false,
            };
            return match key {
                PubKey::Ec { .. } => verify_der_sig(key, hash, tbs, &self.sig),
                _ => false,
            };
        }
        if oid_bytes.len() == 9 && oid_bytes[..8] == PKCS1 {
            let (n, e) = match key {
                PubKey::Rsa { n, e } => (n, e),
                _ => return false,
            };
            return match oid_bytes[8] {
                11 => rsa_pkcs1_verify(n, e, Hash::Sha256, tbs, &self.sig),
                12 => rsa_pkcs1_verify(n, e, Hash::Sha384, tbs, &self.sig),
                13 => rsa_pkcs1_verify(n, e, Hash::Sha512, tbs, &self.sig),
                10 => match pss_params(&self.sig_alg, oid.end, alg.end) {
                    Some((hash, salt)) => rsa_pss_verify(n, e, hash, salt, tbs, &self.sig),
                    None => false,
                },
                _ => false,
            };
        }
        false
    }
}

/// RSASSA-PSS parameters (RFC 4055): the digest and the salt length. MGF1 must use the same digest; the trailer field must be 1.
fn pss_params(alg: &[u8], from: usize, limit: usize) -> Option<(Hash, usize)> {
    let mut hash = Hash::Sha1;
    let mut mgf_hash = Hash::Sha1;
    let mut salt: usize = 20;
    if from < limit {
        let params = tlv_at(alg, from).ok()?;
        if params.tag != 0x30 || params.end != limit {
            return None;
        }
        let mut p = params.start;
        while p < params.end {
            let f = tlv_at(alg, p).ok()?;
            p = f.end;
            match f.tag {
                0xa0 => {
                    let a = tlv_at(alg, f.start).ok()?;
                    hash = hash_of_alg(alg, &a)?;
                }
                0xa1 => {
                    let a = tlv_at(alg, f.start).ok()?;
                    let oid = tlv_at(alg, a.start).ok()?;
                    if alg[oid.start..oid.end] != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08] {
                        return None;
                    }
                    let inner = tlv_at(alg, oid.end).ok()?;
                    mgf_hash = hash_of_alg(alg, &inner)?;
                }
                0xa2 => {
                    let i = tlv_at(alg, f.start).ok()?;
                    if i.tag != 0x02 || i.end - i.start > 4 {
                        return None;
                    }
                    salt = alg[i.start..i.end].iter().fold(0usize, |a, b| (a << 8) | *b as usize);
                }
                0xa3 => {
                    let i = tlv_at(alg, f.start).ok()?;
                    if i.tag != 0x02 || alg[i.start..i.end] != [1] {
                        return None;
                    }
                }
                _ => return None,
            }
        }
    }
    if hash != mgf_hash {
        return None;
    }
    Some((hash, salt))
}

fn hash_of_alg(b: &[u8], a: &Tlv) -> Option<Hash> {
    if a.tag != 0x30 {
        return None;
    }
    let oid = tlv_at(b, a.start).ok()?;
    match &b[oid.start..oid.end] {
        [0x2b, 0x0e, 0x03, 0x02, 0x1a] => Some(Hash::Sha1),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Some(Hash::Sha256),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Some(Hash::Sha384),
        [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Some(Hash::Sha512),
        _ => None,
    }
}

// ───────────────────────────── PEM

/// Every `-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----` block of `text` (lazy match, in order).
pub fn pem_blocks(text: &str) -> Vec<&str> {
    const B: &str = "-----BEGIN CERTIFICATE-----";
    const E: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = text;
    let mut base = 0usize;
    while let Some(i) = rest.find(B) {
        let after = i + B.len();
        match rest[after..].find(E) {
            Some(j) => {
                let end = after + j + E.len();
                out.push(&text[base + i..base + end]);
                base += end;
                rest = &text[base..];
            }
            None => break,
        }
    }
    out
}

pub fn pem_to_der(block: &str) -> Result<Vec<u8>, String> {
    const B: &str = "-----BEGIN CERTIFICATE-----";
    const E: &str = "-----END CERTIFICATE-----";
    let err = || "error:1E08010C:DECODER routines::unsupported".to_string();
    let s = block.trim();
    let body = s.strip_prefix(B).and_then(|x| x.strip_suffix(E)).ok_or_else(err)?;
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    b64_strict(&compact).ok_or_else(err)
}

/// A single PEM certificate or a DER certificate given as text is not accepted; a PEM `PUBLIC KEY` block is.
pub fn pem_public_key(text: &str) -> Result<PubKey, String> {
    const B: &str = "-----BEGIN PUBLIC KEY-----";
    const E: &str = "-----END PUBLIC KEY-----";
    let err = || "error:1E08010C:DECODER routines::unsupported".to_string();
    let s = text.trim();
    let body = s.strip_prefix(B).and_then(|x| x.strip_suffix(E)).ok_or_else(err)?;
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    parse_spki(&b64_strict(&compact).ok_or_else(err)?)
}

// ───────────────────────────── names

fn short_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x04] => "SN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x09] => "street",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x55, 0x04, 0x0c] => "title",
        [0x55, 0x04, 0x11] => "postalCode",
        [0x55, 0x04, 0x2a] => "GN",
        [0x55, 0x04, 0x2b] => "initials",
        [0x55, 0x04, 0x2e] => "dnQualifier",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01] => "UID",
        _ => return None,
    })
}

fn oid_dotted(b: &[u8]) -> String {
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

fn escape_2253(v: &str) -> String {
    let cs: Vec<char> = v.chars().collect();
    let mut out = String::new();
    for (i, c) in cs.iter().enumerate() {
        let special = matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';');
        let edge = (i == 0 && (*c == ' ' || *c == '#')) || (i + 1 == cs.len() && *c == ' ');
        if special || edge {
            out.push('\\');
            out.push(*c);
        } else if (*c as u32) < 0x20 || *c as u32 == 0x7f {
            out.push_str(&format!("\\{:02X}", *c as u32));
        } else {
            out.push(*c);
        }
    }
    out
}

/// Render a DER `Name` the way Node renders `X509Certificate.subject`: one `SHORTNAME=value` line per attribute.
pub fn name_to_string(name: &[u8]) -> String {
    let mut lines: Vec<String> = Vec::new();
    let outer = match tlv_at(name, 0) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let mut p = outer.start;
    while p < outer.end {
        let set = match tlv_at(name, p) {
            Ok(t) => t,
            Err(_) => break,
        };
        p = set.end;
        let mut q = set.start;
        while q < set.end {
            let ava = match tlv_at(name, q) {
                Ok(t) => t,
                Err(_) => break,
            };
            q = ava.end;
            let oid = match tlv_at(name, ava.start) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let val = match tlv_at(name, oid.end) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let key = match short_name(&name[oid.start..oid.end]) {
                Some(s) => s.to_string(),
                None => oid_dotted(&name[oid.start..oid.end]),
            };
            let raw = &name[val.start..val.end];
            let text = match val.tag {
                0x0c | 0x13 | 0x16 | 0x14 => Some(String::from_utf8_lossy(raw).to_string()),
                0x1e => {
                    let u: Vec<u16> = raw.chunks(2).filter(|c| c.len() == 2).map(|c| ((c[0] as u16) << 8) | c[1] as u16).collect();
                    Some(String::from_utf16_lossy(&u))
                }
                _ => None,
            };
            let rendered = match text {
                Some(t) => escape_2253(&t),
                None => format!("#{}", super::util::hex_lower(&name[oid.end..val.end]).to_uppercase()),
            };
            lines.push(format!("{key}={rendered}"));
        }
    }
    lines.join("\n")
}

/// True iff `point` (uncompressed SEC1) is a valid point of `curve`.
pub fn ec_point_valid(curve: EcCurve, point: &[u8]) -> bool {
    match curve {
        EcCurve::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok(),
        EcCurve::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(point).is_ok(),
        _ => false,
    }
}
