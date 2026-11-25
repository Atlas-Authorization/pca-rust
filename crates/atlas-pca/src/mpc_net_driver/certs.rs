//! Per-run identity material for the TLS mesh: one fresh P-256 key and self-signed certificate per node. Only the PUBLIC
//! certificates are exchanged and pinned (by the SHA-256 of their DER); the key stays on its node. Nothing here is committed:
//! tests and the launcher generate every identity in memory or in a throw-away directory.
use crate::attest::x509::{ecdsa_der_to_raw, ecdsa_verify_raw, EcCurve, Hash};
use base64::Engine;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::SignatureScheme;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A node's PEM key and certificate.
#[derive(Clone)]
pub struct Identity {
    pub key_pem: String,
    pub cert_pem: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").field("key_pem", &"<redacted>").field("cert_pem", &self.cert_pem).finish()
    }
}

/// A fresh P-256 key and self-signed certificate for `cn`.
///
/// shortcut: the certificate keeps the generator's default validity window: the mesh pins certificates by fingerprint and never
/// reads the dates, so a throw-away identity needs no expiry; do not reuse these certificates anywhere that checks dates.
pub fn generate_identity(cn: &str) -> Result<Identity, String> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| format!("keygen: {e}"))?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| format!("cert params: {e}"))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, cn.to_string());
    let cert = params.self_signed(&key).map_err(|e| format!("self-sign: {e}"))?;
    Ok(Identity { key_pem: key.serialize_pem(), cert_pem: cert.pem() })
}

/// Generate an identity and write `<dir>/key.pem` (owner-only on unix) and `<dir>/cert.pem`; returns their paths.
pub fn write_identity(dir: &Path, cn: &str) -> Result<(PathBuf, PathBuf), String> {
    let id = generate_identity(cn)?;
    crate::private_file::create_dir_all_private(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let (kp, cp) = (dir.join("key.pem"), dir.join("cert.pem"));
    write_private(&kp, id.key_pem.as_bytes())?;
    crate::private_file::write_private(&cp, id.cert_pem.as_bytes()).map_err(|e| format!("write {}: {e}", cp.display()))?;
    Ok((kp, cp))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::private_file::write_private(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

pub fn read_pem(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

/// The label and DER bytes of the first PEM block whose label is one of `labels`.
pub fn pem_block(pem: &str, labels: &[&str]) -> Result<(String, Vec<u8>), String> {
    let mut lines = pem.lines().map(str::trim);
    while let Some(l) = lines.next() {
        let Some(label) = l.strip_prefix("-----BEGIN ").and_then(|x| x.strip_suffix("-----")) else { continue };
        if !labels.contains(&label) {
            continue;
        }
        let end = format!("-----END {label}-----");
        let mut body = String::new();
        let mut closed = false;
        for b in lines.by_ref() {
            if b == end {
                closed = true;
                break;
            }
            body.push_str(b);
        }
        if !closed {
            return Err(format!("unterminated PEM block {label}"));
        }
        let der = base64::engine::general_purpose::STANDARD.decode(body.as_bytes()).map_err(|_| "bad PEM base64".to_string())?;
        return Ok((label.to_string(), der));
    }
    Err(format!("no PEM block among {labels:?}"))
}

/// The DER of the (first) certificate of a PEM text.
pub fn cert_der(cert_pem: &str) -> Result<Vec<u8>, String> {
    Ok(pem_block(cert_pem, &["CERTIFICATE"])?.1)
}

/// The pin of a certificate: SHA-256 of its DER.
pub fn fingerprint_der(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

pub fn fingerprint_of(cert_pem: &str) -> Result<[u8; 32], String> {
    Ok(fingerprint_der(&cert_der(cert_pem)?))
}

/// Lowercase hex of a pin.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// A node's private key: usable for the TLS handshake and for signing data with the key the peers pinned.
#[derive(Clone)]
pub struct NodeKey {
    der: Arc<Vec<u8>>,
    pkcs8: bool,
    signing: Option<Arc<dyn rustls::sign::SigningKey>>,
}

impl NodeKey {
    /// Load a PKCS#8 (`PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`) PEM key.
    pub fn from_pem(pem: &str) -> Result<NodeKey, String> {
        let (label, der) = pem_block(pem, &["PRIVATE KEY", "EC PRIVATE KEY"])?;
        let k = NodeKey { der: Arc::new(der), pkcs8: label == "PRIVATE KEY", signing: None };
        let provider = rustls::crypto::ring::default_provider();
        let signing = provider.key_provider.load_private_key(k.der()).map_err(|e| format!("private key: {e}"))?;
        Ok(NodeKey { signing: Some(signing), ..k })
    }

    /// The key as rustls wants it for a TLS configuration.
    pub fn der(&self) -> PrivateKeyDer<'static> {
        if self.pkcs8 {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.der.to_vec()))
        } else {
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(self.der.to_vec()))
        }
    }

    /// ECDSA-P256 / SHA-256 signature (ASN.1 DER) over `data`; verifiable against the pinned certificate with [`verify`].
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let signer = self
            .signing
            .as_ref()
            .ok_or("no key loaded")?
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .ok_or("the identity key is not an ECDSA P-256 key")?;
        signer.sign(data).map_err(|e| format!("sign: {e}"))
    }
}

/// One DER element: its tag, its content and what follows it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&l0, rest) = rest.split_first()?;
    let (len, rest) = if l0 < 0x80 {
        (l0 as usize, rest)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 3 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |a, x| (a << 8) | *x as usize), &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// The uncompressed SEC1 point of the subject public key of a certificate (the key must be a 65-byte bit string).
fn spki_point(cert: &[u8]) -> Option<Vec<u8>> {
    let (_, cert_c, _) = tlv(cert)?;
    let (_, tbs, _) = tlv(cert_c)?;
    let mut rest = tbs;
    let (t, _, r) = tlv(rest)?;
    if t == 0xA0 {
        rest = r; // the optional explicit version
    }
    for _ in 0..5 {
        // serial number, signature algorithm, issuer, validity, subject
        rest = tlv(rest)?.2;
    }
    let (_, spki, _) = tlv(rest)?;
    let (_, _alg, r) = tlv(spki)?;
    let (tag, bits, _) = tlv(r)?;
    if tag != 0x03 || bits.len() != 66 || bits[0] != 0 || bits[1] != 0x04 {
        return None;
    }
    Some(bits[1..].to_vec())
}

/// Verify an ECDSA-P256 / SHA-256 DER signature over `data` against the public key of the certificate `cert_der`. False on any failure.
pub fn verify(cert_der: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let Some(point) = spki_point(cert_der) else { return false };
    let Some(rs) = ecdsa_der_to_raw(sig, EcCurve::P256.coord_len()) else { return false };
    ecdsa_verify_raw(EcCurve::P256, &point, &Hash::Sha256.digest(data), &rs)
}

#[cfg(test)]
mod owner_only_tests {
    #[test]
    fn the_party_key_and_certificate_are_owner_only() {
        let d = std::env::temp_dir().join(format!("mpc-identity-{}", std::process::id())).join("party");
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
        let (k, c) = super::write_identity(&d, "p1").unwrap();
        for p in [d.as_path(), k.as_path(), c.as_path()] {
            crate::private_file::assert_owner_only(p);
        }
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }
}
