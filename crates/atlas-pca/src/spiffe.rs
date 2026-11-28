//! SPIFFE / SPIRE workload identity for PCA: SPIFFE ID parsing, JWT-SVID and X.509-SVID verification, the SVID -> PCA holder
//! binding, trust-bundle and revocation caches that fail closed, and SPIFFE evidence for blueprint admission.
//!
//! Every failure is a [`SpiffeError`] with the reference's `code` (a SPIFFE code, a JOSE `ERR_*` code, or none for what the
//! reference raises as a plain runtime error). Only an SVID returned by [`verify_x509_svid`] / [`verify_jwt_svid`] can be bound
//! to a holder: a parse-only SVID is refused. Revocation checks and cache fetches are synchronous closures.
use crate::attest::der::x509_valid_at;
use crate::attest::ocsp::delegated_issued_by_ber as delegated_issued_by;
use crate::attest::x509::{pem_blocks, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use crate::jose::{assert_canonical_compact_jws, DEFAULT_MAX_JWS_BYTES};
use crate::oauth::js_str;
use crate::oidc::{KeyResolver, LocalJwkSet};
use crate::sdjwt::{jwt_verify_with, Claims, SdJwtKey};
use crate::{b64_encode, decode_b64u_strict};
use serde_json::{json, Map, Value};
use sha2::Digest;
use std::collections::HashSet;
use std::sync::Mutex;

/// A refusal: `code` is the reference's error code (`None` where the reference throws a plain runtime error).
#[derive(Debug, Clone, PartialEq)]
pub struct SpiffeError {
    pub code: Option<String>,
    pub message: String,
}

impl std::fmt::Display for SpiffeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SpiffeError {}

impl SpiffeError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        SpiffeError { code: Some(code.to_string()), message: message.into() }
    }
    /// A failure without a code (a fetch that failed, a runtime type error).
    pub fn plain(message: impl Into<String>) -> Self {
        SpiffeError { code: None, message: message.into() }
    }
}

fn err(code: &str, message: impl Into<String>) -> SpiffeError {
    SpiffeError::new(code, message)
}

// ------------------------------------------------------------------------------------------------- SPIFFE ID

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    pub id: String,
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeId {
    /// `{id, trustDomain, path}`.
    pub fn to_json(&self) -> Value {
        json!({ "id": self.id, "trustDomain": self.trust_domain, "path": self.path })
    }
}

const SPIFFE_SCHEME: &str = "spiffe://";
const MAX_SPIFFE_ID_LENGTH: usize = 2048;
const MAX_TRUST_DOMAIN_LENGTH: usize = 255;

fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Parse and validate a SPIFFE ID (SPIFFE-ID spec §2): lowercase trust domain of `[a-z0-9._-]`, path segments of
/// `[a-zA-Z0-9._-]`, no empty / `.` / `..` segment, no trailing slash, at most 2048 (UTF-16) units.
pub fn parse_spiffe_id(s: &str) -> Result<SpiffeId, SpiffeError> {
    if s.is_empty() {
        return Err(err("malformed_spiffe_id", "SPIFFE ID must be a non-empty string"));
    }
    if js_len(s) > MAX_SPIFFE_ID_LENGTH {
        return Err(err("id_too_long", format!("SPIFFE ID exceeds {MAX_SPIFFE_ID_LENGTH} bytes")));
    }
    let Some(rest) = s.strip_prefix(SPIFFE_SCHEME) else { return Err(err("malformed_spiffe_id", format!("SPIFFE ID must begin with \"{SPIFFE_SCHEME}\""))) };
    let (td, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if td.is_empty() {
        return Err(err("empty_trust_domain", "SPIFFE ID has an empty trust domain"));
    }
    if js_len(td) > MAX_TRUST_DOMAIN_LENGTH {
        return Err(err("trust_domain_too_long", format!("trust domain exceeds {MAX_TRUST_DOMAIN_LENGTH} bytes")));
    }
    if !td.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) {
        return Err(err("invalid_trust_domain", format!("trust domain \"{td}\" must be lowercase and contain only [a-z0-9._-]")));
    }
    if !path.is_empty() {
        if path.ends_with('/') {
            return Err(err("invalid_path", "SPIFFE ID path must not end with a trailing slash"));
        }
        for seg in path.split('/').skip(1) {
            if seg.is_empty() {
                return Err(err("invalid_path", "SPIFFE ID path must not contain an empty segment"));
            }
            if seg == "." || seg == ".." {
                return Err(err("invalid_path", "SPIFFE ID path must not contain a \".\" or \"..\" segment"));
            }
            if !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                return Err(err("invalid_path", format!("SPIFFE ID path segment \"{seg}\" contains an invalid character")));
            }
        }
    }
    Ok(SpiffeId { id: format!("{SPIFFE_SCHEME}{td}{path}"), trust_domain: td.into(), path: path.into() })
}

// ------------------------------------------------------------------------------------------------- certificates

/// A certificate as given: PEM text or DER bytes (bytes may also hold PEM text).
#[derive(Debug, Clone, Copy)]
pub enum CertInput<'a> {
    Pem(&'a str),
    Der(&'a [u8]),
}

/// `new X509Certificate(input)`: the first PEM certificate block of the input, else the input as DER.
fn to_certificate(c: &CertInput) -> Result<Cert, SpiffeError> {
    let malformed = |e: String| err("malformed_certificate", format!("cannot parse certificate: {e}"));
    let text = match c {
        CertInput::Pem(s) => Some(*s),
        CertInput::Der(b) => std::str::from_utf8(b).ok(),
    };
    if let Some(block) = text.and_then(|t| pem_blocks(t).first().copied()) {
        let cert = Cert::from_pem(block).map_err(malformed)?;
        check_ext_booleans(&cert.raw).map_err(malformed)?;
        return Ok(cert);
    }
    let bytes = match c {
        CertInput::Pem(s) => s.as_bytes(),
        CertInput::Der(b) => *b,
    };
    Cert::from_der(bytes).map_err(malformed)
}

/// What the SVID rules read from a certificate's extensions (a strict DER walk: anything malformed is refused).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CertFacts {
    pub basic_constraints_present: bool,
    pub is_ca: bool,
    pub path_len: Option<u64>,
    pub key_usage_present: bool,
    pub digital_signature: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub uri_sans: Vec<String>,
    pub unknown_critical: Vec<String>,
}

#[derive(Clone, Copy)]
struct Tlv {
    tag: u8,
    start: usize,
    end: usize,
}

fn read_tlv(buf: &[u8], off: usize, limit: usize) -> Result<Tlv, String> {
    if off + 2 > limit {
        return Err("der: truncated header".into());
    }
    let tag = buf[off];
    if tag & 0x1f == 0x1f {
        return Err("der: high-tag-number form is not supported".into());
    }
    let mut len = buf[off + 1] as usize;
    let mut p = off + 2;
    if len & 0x80 != 0 {
        let n = len & 0x7f;
        if n == 0 || n > 4 {
            return Err("der: unsupported length form".into());
        }
        if p + n > limit {
            return Err("der: truncated length".into());
        }
        len = buf[p..p + n].iter().fold(0usize, |a, b| a * 256 + *b as usize);
        p += n;
    }
    if p + len > limit {
        return Err("der: content exceeds container".into());
    }
    Ok(Tlv { tag, start: p, end: p + len })
}

fn children(buf: &[u8], parent: Tlv) -> Result<Vec<Tlv>, String> {
    let mut out = Vec::new();
    let mut off = parent.start;
    while off < parent.end {
        let t = read_tlv(buf, off, parent.end)?;
        out.push(t);
        off = t.end;
    }
    Ok(out)
}

const KNOWN_CRITICAL: [&str; 6] = ["551d0f", "551d11", "551d13", "551d25", "551d0e", "551d23"];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// OpenSSL refuses an extension whose critical BOOLEAN is not one octet at parse time.
fn check_ext_booleans(der: &[u8]) -> Result<(), String> {
    let Ok(cert) = read_tlv(der, 0, der.len()) else { return Ok(()) };
    let Some(tbs) = children(der, cert).ok().and_then(|c| c.first().copied()) else { return Ok(()) };
    let Some(wrap) = children(der, tbs).ok().and_then(|c| c.into_iter().find(|t| t.tag == 0xa3)) else { return Ok(()) };
    let Some(ext_seq) = children(der, wrap).ok().and_then(|c| c.first().copied()) else { return Ok(()) };
    for ext in children(der, ext_seq).unwrap_or_default() {
        let parts = children(der, ext).unwrap_or_default();
        if parts.len() == 3 && parts[1].tag == 0x01 && parts[1].end - parts[1].start != 1 {
            return Err("error:0680006A:asn1 encoding routines::boolean is wrong length".into());
        }
    }
    Ok(())
}

/// The extension facts of one DER certificate (keyUsage, subjectAltName URIs, basicConstraints, unknown critical OIDs).
pub fn read_cert_facts(der: &[u8]) -> Result<CertFacts, String> {
    let cert = read_tlv(der, 0, der.len())?;
    if cert.tag != 0x30 || cert.end != der.len() {
        return Err("der: certificate is not a single SEQUENCE".into());
    }
    let tbs = *children(der, cert)?.first().filter(|t| t.tag == 0x30).ok_or("der: missing tbsCertificate")?;
    let mut f = CertFacts::default();
    let Some(wrap) = children(der, tbs)?.into_iter().find(|t| t.tag == 0xa3) else { return Ok(f) };
    let ext_seq = *children(der, wrap)?.first().filter(|t| t.tag == 0x30).ok_or("der: malformed extensions")?;
    let mut seen = HashSet::new();
    for ext in children(der, ext_seq)? {
        let parts = children(der, ext)?;
        let oid_t = *parts.first().filter(|t| t.tag == 0x06).ok_or("der: malformed extension")?;
        let oid = hex(&der[oid_t.start..oid_t.end]);
        if !seen.insert(oid.clone()) {
            return Err("der: duplicate extension".into());
        }
        let critical = parts.len() == 3 && parts[1].tag == 0x01 && der.get(parts[1].start).is_some_and(|b| *b != 0);
        let value = *parts.last().filter(|t| t.tag == 0x04).ok_or("der: malformed extension value")?;
        if critical && !KNOWN_CRITICAL.contains(&oid.as_str()) {
            f.unknown_critical.push(oid.clone());
        }
        let inner = read_tlv(der, value.start, value.end)?;
        match oid.as_str() {
            "551d13" => {
                f.basic_constraints_present = true;
                for c in children(der, inner)? {
                    if c.tag == 0x01 {
                        f.is_ca = der.get(c.start) == Some(&0xff);
                    } else if c.tag == 0x02 {
                        f.path_len = Some(der[c.start..c.end].iter().fold(0u64, |a, b| a.saturating_mul(256).saturating_add(*b as u64)));
                    }
                }
            }
            "551d0f" => {
                if inner.tag != 0x03 || inner.end - inner.start < 2 {
                    return Err("der: malformed keyUsage".into());
                }
                let b0 = der[inner.start + 1];
                f.key_usage_present = true;
                f.digital_signature = b0 & 0x80 != 0;
                f.key_cert_sign = b0 & 0x04 != 0;
                f.crl_sign = b0 & 0x02 != 0;
            }
            "551d11" => {
                for gn in children(der, inner)? {
                    if gn.tag == 0x86 {
                        f.uri_sans.push(der[gn.start..gn.end].iter().map(|b| *b as char).collect());
                        // latin1
                    }
                }
            }
            _ => {}
        }
    }
    Ok(f)
}

fn facts_of(c: &Cert) -> Result<CertFacts, SpiffeError> {
    read_cert_facts(&c.raw).map_err(|e| err("malformed_certificate", format!("cannot read certificate extensions: {e}")))
}

fn validate_leaf(c: &Cert) -> Result<SpiffeId, SpiffeError> {
    let f = facts_of(c)?;
    if !f.unknown_critical.is_empty() {
        return Err(err("unsupported_critical_extension", format!("certificate has an unsupported critical extension ({})", f.unknown_critical.join(", "))));
    }
    match f.uri_sans.len() {
        0 => return Err(err("no_uri_san", "X.509-SVID certificate has no URI SAN")),
        1 => {}
        n => return Err(err("multiple_uri_san", format!("X.509-SVID certificate must have exactly one URI SAN, found {n}"))),
    }
    let id = parse_spiffe_id(&f.uri_sans[0])?;
    if id.path.is_empty() {
        return Err(err("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path"));
    }
    if f.is_ca {
        return Err(err("leaf_is_ca", "leaf certificate must not have the CA flag set to true"));
    }
    if !f.digital_signature {
        return Err(err("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage"));
    }
    if f.key_cert_sign {
        return Err(err("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage"));
    }
    if f.crl_sign {
        return Err(err("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage"));
    }
    Ok(id)
}

fn validate_signer(c: &Cert, label: &str) -> Result<CertFacts, SpiffeError> {
    let f = facts_of(c)?;
    if !f.unknown_critical.is_empty() {
        return Err(err("unsupported_critical_extension", format!("{label} has an unsupported critical extension ({})", f.unknown_critical.join(", "))));
    }
    if !f.is_ca {
        return Err(err("chain_not_ca", format!("{label} must have the CA flag set to true")));
    }
    if !f.key_usage_present || !f.key_cert_sign {
        return Err(err("chain_no_key_cert_sign", format!("{label} must have 'keyCertSign' set as key usage")));
    }
    Ok(f)
}

fn spki_b64(c: &Cert) -> Result<String, SpiffeError> {
    c.public_key().map(|k| b64_encode(&k.spki_der())).map_err(|e| err("malformed_certificate", format!("cannot parse certificate: {e}")))
}

/// An X.509-SVID: the leaf's SPIFFE ID, the leaf certificate and its SPKI (base64url DER).
#[derive(Debug, Clone)]
pub struct X509Svid {
    pub spiffe_id: SpiffeId,
    pub certificate: Cert,
    pub public_key_der: String,
    verified: bool,
}

/// Parse a leaf X.509-SVID WITHOUT verifying its chain (inspection only: [`svid_to_holder`] refuses the result).
pub fn parse_x509_svid(cert: &CertInput) -> Result<X509Svid, SpiffeError> {
    let certificate = to_certificate(cert)?;
    let spiffe_id = validate_leaf(&certificate)?;
    let public_key_der = spki_b64(&certificate)?;
    Ok(X509Svid { spiffe_id, certificate, public_key_der, verified: false })
}

fn certs_of(input: &CertInput) -> Result<Vec<Cert>, SpiffeError> {
    match input {
        CertInput::Pem(s) => {
            let blocks = pem_blocks(s);
            if blocks.is_empty() {
                return Err(err("malformed_certificate", "no PEM certificate found"));
            }
            blocks.iter().map(|b| to_certificate(&CertInput::Pem(b))).collect()
        }
        d => Ok(vec![to_certificate(d)?]),
    }
}

/// A revocation check: `true` = revoked, `false` = not revoked; any other value or an error refuses (fail closed).
pub type RevocationCheck<'a> = &'a dyn Fn(&Value) -> Result<Value, String>;

fn ask_revocation(check: RevocationCheck, subject: &Value) -> Result<bool, SpiffeError> {
    match check(subject) {
        Err(e) => Err(err("revocation_unavailable", format!("revocation check failed: {e}"))),
        Ok(Value::Bool(b)) => Ok(b),
        Ok(_) => Err(err("revocation_unavailable", "revocation check did not return a boolean")),
    }
}

/// [`verify_x509_svid`] options. `roots` is the trust bundle's X.509 authorities; `now_ms` defaults to the clock,
/// `max_chain_length` to 8. The revocation check sees `{spiffeId, serialNumber, fingerprint256, position, isLeaf}` per certificate.
#[derive(Clone, Copy, Default)]
pub struct X509SvidOptions<'a> {
    pub trust_domain: Option<&'a str>,
    pub roots: &'a [CertInput<'a>],
    pub now_ms: Option<f64>,
    pub max_chain_length: Option<f64>,
    pub revocation: Option<RevocationCheck<'a>>,
}

fn clock_ms() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_millis() as f64)
}

fn fingerprint256(c: &Cert) -> String {
    sha2::Sha256::digest(&c.raw).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Verify an X.509-SVID chain (leaf first, then intermediates) against the trust bundle's authorities: the leaf SVID rules,
/// the trust domain, every validity window, CA / keyCertSign / pathLen of each signer, each signature link, and a chain that
/// ends at (or is signed by) a bundle authority. A leaf cannot be its own anchor.
pub fn verify_x509_svid(chain: &[CertInput], o: &X509SvidOptions) -> Result<X509Svid, SpiffeError> {
    let now = o.now_ms.unwrap_or_else(clock_ms);
    let mut items = Vec::new();
    for c in chain {
        items.extend(certs_of(c)?);
    }
    if items.is_empty() {
        return Err(err("chain_empty", "certificate chain is empty"));
    }
    if !((items.len() as f64) <= o.max_chain_length.unwrap_or(8.0)) {
        return Err(err("chain_too_long", "certificate chain is too long"));
    }
    let leaf = &items[0];
    let id = validate_leaf(leaf)?;
    if Some(id.trust_domain.as_str()) != o.trust_domain {
        return Err(err(
            "chain_trust_domain_mismatch",
            format!("SPIFFE ID trust domain '{}' is not '{}'", id.trust_domain, o.trust_domain.unwrap_or("undefined")),
        ));
    }
    let mut roots = Vec::new();
    for r in o.roots {
        roots.extend(certs_of(r)?);
    }
    if roots.is_empty() {
        return Err(err("chain_untrusted_root", "trust bundle has no X.509 authorities"));
    }
    if items.iter().any(|c| !x509_valid_at(&c.raw, now, 0.0)) {
        return Err(err("chain_expired", "a certificate in the chain is not within its validity period"));
    }
    for (i, c) in items.iter().enumerate().skip(1) {
        let f = validate_signer(c, &format!("signing certificate #{i}"))?;
        if f.path_len.is_some_and(|p| (i as u64 - 1) > p) {
            return Err(err("chain_path_len", format!("signing certificate #{i} pathLenConstraint exceeded")));
        }
    }
    for i in 0..items.len() - 1 {
        if !delegated_issued_by(&items[i], &items[i + 1]) {
            return Err(err("chain_signature", format!("certificate #{i} is not signed by certificate #{}", i + 1)));
        }
    }
    let top = &items[items.len() - 1];
    if items.len() == 1 && roots.iter().any(|r| r.raw == leaf.raw) {
        return Err(err("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor"));
    }
    let top_is_anchor = items.len() > 1 && roots.iter().any(|r| r.raw == top.raw);
    if !top_is_anchor {
        let Some(signer) = roots.iter().find(|r| delegated_issued_by(top, r)) else {
            return Err(err("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle"));
        };
        if !x509_valid_at(&signer.raw, now, 0.0) {
            return Err(err("chain_expired", "the trust bundle authority is not within its validity period"));
        }
        let f = validate_signer(signer, "trust bundle authority")?;
        if f.path_len.is_some_and(|p| (items.len() as u64 - 1) > p) {
            return Err(err("chain_path_len", "trust bundle authority pathLenConstraint exceeded"));
        }
    }
    if let Some(check) = o.revocation {
        for (i, c) in items.iter().enumerate() {
            let subject = json!({ "spiffeId": id.id, "serialNumber": c.serial_hex(), "fingerprint256": fingerprint256(c), "position": i, "isLeaf": i == 0 });
            if ask_revocation(check, &subject)? {
                return Err(if i == 0 {
                    err("svid_revoked", format!("X.509-SVID for {} is revoked", id.id))
                } else {
                    err("chain_revoked", format!("signing certificate #{i} of the chain is revoked"))
                });
            }
        }
    }
    let public_key_der = spki_b64(leaf)?;
    Ok(X509Svid { spiffe_id: id, certificate: items.swap_remove(0), public_key_der, verified: true })
}

// ------------------------------------------------------------------------------------------------- JWT-SVID

pub const JWT_SVID_ALGORITHMS: [&str; 9] = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"];

/// The JWT-SVID verification key: one public JWK, or a resolver (a [`LocalJwkSet`], a [`TrustBundleSource`], your own).
pub enum SvidKey<'a> {
    Jwk(Value),
    Resolver(&'a dyn KeyResolver),
}

/// [`verify_jwt_svid`] options (JSON-typed where the reference accepts loose input). `audience` is a string or an array,
/// `trust_domain` must be a non-empty string, `algorithms` defaults to [`JWT_SVID_ALGORITHMS`] (`none` / HS* refused),
/// `clock_tolerance` is seconds or a time-period string. The revocation check sees `{spiffeId, jti?, expiresAt, tokenHash}`.
pub struct JwtSvidOptions<'a> {
    pub audience: &'a Value,
    pub key: Option<SvidKey<'a>>,
    pub trust_domain: &'a Value,
    pub now_ms: Option<f64>,
    pub algorithms: Option<&'a Value>,
    pub clock_tolerance: Option<&'a Value>,
    pub revocation: Option<RevocationCheck<'a>>,
}

#[derive(Debug, Clone)]
pub struct JwtSvid {
    pub spiffe_id: SpiffeId,
    pub claims: Map<String, Value>,
    pub audience: Vec<Value>,
    pub expires_at: Value,
    verified: bool,
}

/// The JOSE library's error code for one of its refusal texts.
fn jose_code(m: &str) -> Option<&'static str> {
    Some(match m {
        "signature verification failed" => "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
        "\"alg\" (Algorithm) Header Parameter value not allowed" => "ERR_JOSE_ALG_NOT_ALLOWED",
        "\"exp\" claim timestamp check failed" => "ERR_JWT_EXPIRED",
        "no applicable key found in the JSON Web Key Set" => "ERR_JWKS_NO_MATCHING_KEY",
        "multiple matching keys found in the JSON Web Key Set" => "ERR_JWKS_MULTIPLE_MATCHING_KEYS",
        "JWTs MUST NOT use unencoded payload" => "ERR_JWT_INVALID",
        "JSON Web Key Set malformed" => "ERR_JWKS_INVALID",
        m if m.starts_with("Extension Header Parameter") && m.ends_with("is not recognized") => "ERR_JOSE_NOT_SUPPORTED",
        m if m.starts_with("JWS \"alg\"") || m.starts_with("\"crit\"") || m.starts_with("Extension Header Parameter") || m.starts_with("The \"b64\"") => {
            "ERR_JWS_INVALID"
        }
        m if m.starts_with("missing required")
            || m.starts_with("unexpected \"aud\"")
            || m.ends_with("claim must be a number")
            || m == "\"nbf\" claim timestamp check failed" =>
        {
            "ERR_JWT_CLAIM_VALIDATION_FAILED"
        }
        _ => return None,
    })
}

/// Verify a JWT-SVID (SPIFFE JWT-SVID spec): the canonical compact-JWS gate, signature (asymmetric algorithms only), `aud`
/// (mandatory), `exp` (mandatory), `typ` (absent, `JWT` or `JOSE`), `sub` a valid SPIFFE ID in the pinned trust domain, then
/// the revocation check when given.
pub fn verify_jwt_svid(token: &Value, o: &JwtSvidOptions) -> Result<JwtSvid, SpiffeError> {
    let td = match o.trust_domain {
        Value::String(s) if !s.is_empty() => s.as_str(),
        _ => {
            return Err(err(
                "missing_trust_domain",
                "verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)",
            ))
        }
    };
    let list: Vec<Value> = match o.audience {
        Value::String(_) => vec![o.audience.clone()],
        Value::Array(a) => a.clone(),
        v => return Err(SpiffeError::plain(format!("verifyJwtSvid: audience must be a string or an array, got {}", js_str(v)))),
    };
    if list.is_empty() || list.iter().any(|a| a.as_str() == Some("")) {
        return Err(err("missing_audience", "verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)"));
    }
    let default_algs = json!(JWT_SVID_ALGORITHMS);
    let algorithms = o.algorithms.unwrap_or(&default_algs);
    let Some(algs) = algorithms.as_array() else { return Err(SpiffeError::plain("algorithms.find is not a function")) };
    let mut bad = None;
    for a in algs {
        let Some(s) = a.as_str() else { return Err(SpiffeError::plain("a.toUpperCase is not a function")) };
        if s == "none" || s.to_uppercase().starts_with("HS") {
            bad = Some(s);
            break;
        }
    }
    if bad.is_some() || algs.is_empty() {
        return Err(err("forbidden_algorithm", format!("JWT-SVIDs must not use {}", bad.unwrap_or("an empty algorithm list"))));
    }
    let jws = assert_canonical_compact_jws(token, 3, DEFAULT_MAX_JWS_BYTES, true).map_err(|e| err("malformed_token", e))?;
    let Some(key) = &o.key else { return Err(SpiffeError::plain("verifyJwtSvid requires a key")) };
    let key_for = |h: &Map<String, Value>| -> Result<SdJwtKey, String> {
        match key {
            SvidKey::Jwk(j) => Ok(SdJwtKey::Jwk(j.clone())),
            SvidKey::Resolver(r) => r.resolve(h).map(SdJwtKey::Jwk).map_err(|e| e.message),
        }
    };
    let now = o.now_ms.unwrap_or_else(clock_ms);
    if !now.is_finite() {
        return Err(err("malformed_token", "verifyJwtSvid: currentDate must be a valid Date"));
    }
    let claims = Claims { audience: Some(o.audience), tolerance: o.clock_tolerance, now_sec: (now / 1000.0).floor() };
    jwt_verify_with(&jws, &key_for, algorithms, &claims).map_err(|m| SpiffeError { code: jose_code(&m).map(String::from), message: m })?;
    if let Some(t) = jws.header.get("typ") {
        if t != "JWT" && t != "JOSE" {
            return Err(err("invalid_typ", format!("JWT-SVID header typ must be JWT or JOSE, got '{}'", js_str(t))));
        }
    }
    let payload = jws.payload.clone().expect("json payload");
    let Some(exp) = payload.get("exp").filter(|e| e.is_number()).cloned() else {
        return Err(err("missing_exp", "JWT-SVID is missing the required \"exp\" claim"));
    };
    let Some(sub) = payload.get("sub").and_then(Value::as_str) else { return Err(err("invalid_subject", "JWT-SVID \"sub\" must be a string SPIFFE ID")) };
    let id = parse_spiffe_id(sub).map_err(|e| err("invalid_subject", format!("JWT-SVID \"sub\" is not a valid SPIFFE ID: {}", e.message)))?;
    if id.trust_domain != td {
        return Err(err("trust_domain_mismatch", format!("JWT-SVID trust domain \"{}\" does not match expected \"{td}\"", id.trust_domain)));
    }
    let audience = match payload.get("aud") {
        None => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(a) => vec![a.clone()],
    };
    if let Some(check) = o.revocation {
        let mut subject = Map::new();
        subject.insert("spiffeId".into(), json!(id.id));
        if let Some(j) = payload.get("jti").filter(|j| j.is_string()) {
            subject.insert("jti".into(), j.clone());
        }
        subject.insert("expiresAt".into(), exp.clone());
        subject.insert("tokenHash".into(), json!(b64_encode(&sha2::Sha256::digest(token.as_str().unwrap_or("").as_bytes()))));
        if ask_revocation(check, &Value::Object(subject))? {
            return Err(err("svid_revoked", format!("JWT-SVID for {} is revoked", id.id)));
        }
    }
    Ok(JwtSvid { spiffe_id: id, claims: payload, audience, expires_at: exp, verified: true })
}

// ------------------------------------------------------------------------------------------------- holder binding

/// A verified SVID, either kind.
#[derive(Debug, Clone)]
pub enum Svid {
    X509(X509Svid),
    Jwt(JwtSvid),
}

/// A holder key as given: raw 32 bytes, or base64url text.
#[derive(Debug, Clone, Copy)]
pub enum HolderKey<'a> {
    Raw(&'a [u8]),
    Text(&'a str),
}

/// The PCA holder an SVID binds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeHolder {
    pub holder: String,
    pub spiffe_id: String,
    pub trust_domain: String,
    pub path: String,
}

impl SpiffeHolder {
    /// `{holder, spiffeId, trustDomain, path}`.
    pub fn to_json(&self) -> Value {
        json!({ "holder": self.holder, "spiffeId": self.spiffe_id, "trustDomain": self.trust_domain, "path": self.path })
    }
}

fn normalize_holder_key(k: &HolderKey) -> Result<String, SpiffeError> {
    match k {
        HolderKey::Raw(b) if b.len() == 32 => Ok(b64_encode(b)),
        HolderKey::Raw(_) => Err(err("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key")),
        HolderKey::Text(s) => decode_b64u_strict(s, Some(32))
            .map(|b| b64_encode(&b))
            .ok_or_else(|| err("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url")),
    }
}

/// The bytes an X.509-SVID key signs to bind a different PCA holder key: `pca-spiffe-holder-binding-v1\n<id>\n<holder>`.
pub fn holder_binding_message(spiffe_id: &str, holder: &str) -> Vec<u8> {
    format!("pca-spiffe-holder-binding-v1\n{spiffe_id}\n{holder}").into_bytes()
}

fn ed25519_raw_of_cert(c: &Cert) -> Option<String> {
    match c.public_key() {
        Ok(PubKey::Ed25519(pk)) if pk.len() == 32 => Some(b64_encode(&pk)),
        _ => None,
    }
}

fn proof_verifies(c: &Cert, msg: &[u8], sig: &[u8]) -> bool {
    match c.public_key() {
        Ok(PubKey::Ed25519(pk)) => match (<[u8; 32]>::try_from(pk.as_slice()), <[u8; 64]>::try_from(sig)) {
            (Ok(pk), Ok(s)) => crate::verify_ed25519_strict(&pk, msg, &s),
            _ => false,
        },
        Ok(k @ PubKey::Ec { .. }) => {
            let hash = if matches!(&k, PubKey::Ec { curve: EcCurve::P384, .. }) { Hash::Sha384 } else { Hash::Sha256 };
            verify_p1363_sig(&k, hash, msg, sig)
        }
        Ok(PubKey::Rsa { n, e }) => crate::attest::x509::rsa_pkcs1_verify(&n, &e, Hash::Sha256, msg, sig),
        _ => false,
    }
}

/// Bind a VERIFIED SVID to a PCA holder key. X.509: the holder defaults to the SVID's own Ed25519 key; any other holder key
/// needs `opts.proof` (a signature by the SVID key over [`holder_binding_message`]). JWT: `holder_key` is required and must
/// equal the SVID's `cnf.jwk` (Ed25519) unless `opts.acceptUnboundJwtHolder` is `true`.
pub fn svid_to_holder(svid: &Svid, holder_key: Option<&HolderKey>, opts: &Value) -> Result<SpiffeHolder, SpiffeError> {
    let unverified = || {
        err(
            "unverified_svid",
            "svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)",
        )
    };
    let (id, holder) = match svid {
        Svid::X509(s) => {
            if !s.verified {
                return Err(unverified());
            }
            let cert_ed = ed25519_raw_of_cert(&s.certificate);
            let holder = match holder_key {
                None => normalize_holder_key(&HolderKey::Text(cert_ed.as_deref().ok_or_else(|| {
                    err("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof")
                })?))?,
                Some(k) => {
                    let holder = normalize_holder_key(k)?;
                    if cert_ed.as_deref() != Some(holder.as_str()) {
                        let Some(proof) = opts.get("proof").and_then(Value::as_str) else {
                            return Err(err(
                                "holder_binding_failed",
                                "the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required",
                            ));
                        };
                        let msg = holder_binding_message(&s.spiffe_id.id, &holder);
                        if !decode_b64u_strict(proof, None).is_some_and(|sig| proof_verifies(&s.certificate, &msg, &sig)) {
                            return Err(err("holder_binding_failed", "opts.proof does not verify under the X.509-SVID key"));
                        }
                    }
                    holder
                }
            };
            (&s.spiffe_id, holder)
        }
        Svid::Jwt(s) => {
            if !s.verified {
                return Err(unverified());
            }
            let Some(k) = holder_key else { return Err(err("invalid_holder_key", "a JWT-SVID has no key of its own: pass holderKey")) };
            let holder = normalize_holder_key(k)?;
            let jwk = s.claims.get("cnf").and_then(|c| c.get("jwk"));
            let field = |m: &str| jwk.and_then(|j| j.get(m)).and_then(Value::as_str);
            let bound = field("kty") == Some("OKP") && field("crv") == Some("Ed25519") && field("x") == Some(holder.as_str());
            if !bound && opts.get("acceptUnboundJwtHolder") != Some(&json!(true)) {
                return Err(err(
                    "holder_binding_failed",
                    "the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)",
                ));
            }
            (&s.spiffe_id, holder)
        }
    };
    Ok(SpiffeHolder { holder, spiffe_id: id.id.clone(), trust_domain: id.trust_domain.clone(), path: id.path.clone() })
}

/// The SPIFFE ID of a holder (re-validated).
pub fn holder_to_spiffe_id(holder: &Value) -> Result<String, SpiffeError> {
    match holder.get("spiffeId") {
        Some(Value::String(s)) => parse_spiffe_id(s).map(|i| i.id),
        _ => Err(err("malformed_spiffe_id", "SPIFFE ID must be a non-empty string")),
    }
}

/// The SPIFFE ID of a verified SVID bound to exactly `leaf_holder` (the PCActn leaf holder).
pub fn spiffe_id_for_holder(svid: &Svid, leaf_holder: &str, opts: &Value) -> Result<String, SpiffeError> {
    let h = svid_to_holder(svid, Some(&HolderKey::Text(leaf_holder)), opts)?;
    if h.holder != leaf_holder {
        return Err(err("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder"));
    }
    Ok(h.spiffe_id)
}

/// A workload discharge pin from a verified Ed25519 X.509-SVID: `{label, class: "workload", pk, spiffe_id}`.
pub fn workload_discharge_pin(label: &str, svid: &X509Svid) -> Result<Value, SpiffeError> {
    let h = svid_to_holder(&Svid::X509(svid.clone()), None, &json!({}))?;
    Ok(json!({ "label": label, "class": "workload", "pk": h.holder, "spiffe_id": h.spiffe_id }))
}

/// SPIFFE evidence for blueprint admission.
pub enum SpiffeEvidence<'a> {
    X509 { chain: &'a [CertInput<'a>], verify: X509SvidOptions<'a>, bind: Value },
    Jwt { token: &'a Value, verify: JwtSvidOptions<'a>, bind: Value },
}

/// Verify the evidence and bind it to `instance_key`: `{ok: true, bound: true, identity: {spiffe_id}}`, else
/// `{ok: false, bound: false, reason}` (the refusal's code).
pub fn spiffe_admission_evidence(e: &SpiffeEvidence, instance_key: &str) -> Value {
    let r = (|| {
        let (svid, bind) = match e {
            SpiffeEvidence::X509 { chain, verify, bind } => (Svid::X509(verify_x509_svid(chain, verify)?), bind),
            SpiffeEvidence::Jwt { token, verify, bind } => (Svid::Jwt(verify_jwt_svid(token, verify)?), bind),
        };
        svid_to_holder(&svid, Some(&HolderKey::Text(instance_key)), bind)
    })();
    match r {
        Ok(h) if h.holder != instance_key => json!({ "ok": false, "bound": false, "reason": "SVID is bound to a different key" }),
        Ok(h) => json!({ "ok": true, "bound": true, "identity": { "spiffe_id": h.spiffe_id } }),
        Err(e) => json!({ "ok": false, "bound": false, "reason": e.code.unwrap_or_else(|| "Error".into()) }),
    }
}

// ------------------------------------------------------------------------------------------------- caches

/// A fetch for a cache: the document, or a refusal (a [`SpiffeError`] with a code passes through; one without is wrapped).
pub type CacheFetch = Box<dyn Fn() -> Result<Value, SpiffeError> + Send + Sync>;
/// A clock in epoch milliseconds.
pub type CacheClock = Box<dyn Fn() -> f64 + Send + Sync>;

fn check_windows(refresh_ms: &Value, max_stale_ms: &Value, code: &str) -> Result<(f64, f64), SpiffeError> {
    match (refresh_ms.as_f64(), max_stale_ms.as_f64()) {
        (Some(r), Some(m)) if r > 0.0 && m >= r => Ok((r, m)),
        _ => Err(err(code, "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)")),
    }
}

struct Cache<T> {
    good: Option<(T, f64)>,
    last_failure: Option<SpiffeError>,
}

/// A cached trust bundle (`{jwks?: {keys}, x509Authorities?: [...]}`): refetched every `refresh_ms`, a failed refresh keeps the
/// last good bundle until it is `max_stale_ms` old, then every use refuses.
pub struct TrustBundleSource {
    fetch: CacheFetch,
    refresh_ms: f64,
    max_stale_ms: f64,
    now: CacheClock,
    state: Mutex<Cache<Value>>,
}

fn bundle_usable(b: &Value) -> bool {
    let non_empty = |v: Option<&Value>| v.and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    b.is_object() && (non_empty(b.get("jwks").and_then(|j| j.get("keys"))) || non_empty(b.get("x509Authorities")))
}

/// `createTrustBundleSource({fetch, refreshMs, maxStaleMs, now})`.
pub fn create_trust_bundle_source(
    fetch: CacheFetch,
    refresh_ms: &Value,
    max_stale_ms: &Value,
    now: Option<CacheClock>,
) -> Result<TrustBundleSource, SpiffeError> {
    let (refresh_ms, max_stale_ms) = check_windows(refresh_ms, max_stale_ms, "trust_bundle_unavailable")?;
    Ok(TrustBundleSource {
        fetch,
        refresh_ms,
        max_stale_ms,
        now: now.unwrap_or_else(|| Box::new(clock_ms)),
        state: Mutex::new(Cache { good: None, last_failure: None }),
    })
}

impl TrustBundleSource {
    fn current(&self) -> Result<Value, SpiffeError> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.good.as_ref().is_none_or(|(_, at)| !((self.now)() - at < self.refresh_ms)) {
            match (self.fetch)() {
                Ok(b) if bundle_usable(&b) => {
                    st.good = Some((b, (self.now)()));
                    st.last_failure = None;
                }
                Ok(_) => st.last_failure = Some(err("trust_bundle_invalid", "fetched trust bundle has no authorities")),
                Err(e) if e.code.is_some() => st.last_failure = Some(e),
                Err(e) => st.last_failure = Some(err("trust_bundle_unavailable", format!("trust bundle fetch failed: {}", e.message))),
            }
        }
        match &st.good {
            Some((b, at)) if { let age = (self.now)() - at; age.is_finite() && age <= self.max_stale_ms } => Ok(b.clone()),
            _ => Err(st.last_failure.clone().unwrap_or_else(|| err("trust_bundle_unavailable", "no trust bundle available"))),
        }
    }

    /// The JWT authority for a protected header (the JOSE JWK-Set selection rules).
    pub fn jwt_key(&self, header: &Map<String, Value>) -> Result<Value, SpiffeError> {
        let jwks = self.current()?.get("jwks").cloned().filter(|j| j.get("keys").and_then(Value::as_array).is_some_and(|k| !k.is_empty()));
        let Some(jwks) = jwks else { return Err(err("trust_bundle_invalid", "trust bundle has no JWT authorities")) };
        let set = LocalJwkSet::new(&jwks).map_err(|m| SpiffeError { code: jose_code(&m).map(String::from), message: m })?;
        set.resolve(header).map_err(|e| SpiffeError { code: jose_code(&e.message).map(String::from), message: e.message })
    }

    /// The bundle's X.509 authorities, as given.
    pub fn x509_roots(&self) -> Result<Vec<Value>, SpiffeError> {
        match self.current()?.get("x509Authorities").and_then(Value::as_array) {
            Some(r) if !r.is_empty() => Ok(r.clone()),
            _ => Err(err("trust_bundle_invalid", "trust bundle has no X.509 authorities")),
        }
    }
}

impl KeyResolver for TrustBundleSource {
    fn resolve(&self, header: &Map<String, Value>) -> Result<Value, crate::oidc::OidcError> {
        self.jwt_key(header).map_err(|e| crate::oidc::OidcError { code: e.code.unwrap_or_default(), message: e.message })
    }
}

struct Snapshot {
    fingerprints: HashSet<String>,
    serials: HashSet<String>,
    spiffe_ids: HashSet<String>,
    jtis: HashSet<String>,
    token_hashes: HashSet<String>,
}

fn norm_hex(s: &str) -> String {
    s.replace(':', "").to_uppercase()
}

fn norm_serial(s: &str) -> String {
    let h = norm_hex(s);
    let t = h.trim_start_matches('0');
    if t.is_empty() && !h.is_empty() {
        "0".into()
    } else {
        t.into()
    }
}

fn to_snapshot(list: &Value) -> Result<Snapshot, SpiffeError> {
    let Some(raw) = list.as_object() else { return Err(err("revocation_unavailable", "revocation list must be an object")) };
    let field = |k: &str, norm: fn(&str) -> String| -> Result<HashSet<String>, SpiffeError> {
        match raw.get(k) {
            None => Ok(HashSet::new()),
            Some(Value::Array(a)) if a.iter().all(Value::is_string) => Ok(a.iter().filter_map(Value::as_str).map(norm).collect()),
            Some(_) => Err(err("revocation_unavailable", format!("revocation list field \"{k}\" must be an array of strings"))),
        }
    };
    Ok(Snapshot {
        fingerprints: field("fingerprints", norm_hex)?,
        serials: field("serials", norm_serial)?,
        spiffe_ids: field("spiffeIds", |x| x.to_string())?,
        jtis: field("jtis", |x| x.to_string())?,
        token_hashes: field("tokenHashes", |x| x.to_string())?,
    })
}

/// A cached revocation list (`{fingerprints?, serials?, spiffeIds?, jtis?, tokenHashes?}`): `x509` reads the snapshot (call
/// `ensure_fresh` first), `jwt` refreshes itself; past `max_stale_ms` without a good fetch every check refuses.
pub struct RevocationSource {
    fetch: CacheFetch,
    refresh_ms: f64,
    max_stale_ms: f64,
    now: CacheClock,
    state: Mutex<Cache<Snapshot>>,
}

/// `createRevocationSource({fetch, refreshMs, maxStaleMs, now})`.
pub fn create_revocation_source(fetch: CacheFetch, refresh_ms: &Value, max_stale_ms: &Value, now: Option<CacheClock>) -> Result<RevocationSource, SpiffeError> {
    let (refresh_ms, max_stale_ms) = check_windows(refresh_ms, max_stale_ms, "revocation_unavailable")?;
    Ok(RevocationSource {
        fetch,
        refresh_ms,
        max_stale_ms,
        now: now.unwrap_or_else(|| Box::new(clock_ms)),
        state: Mutex::new(Cache { good: None, last_failure: None }),
    })
}

impl RevocationSource {
    fn run(&self, st: &mut Cache<Snapshot>) {
        match (self.fetch)().and_then(|l| to_snapshot(&l)) {
            Ok(s) => {
                st.good = Some((s, (self.now)()));
                st.last_failure = None;
            }
            Err(e) if e.code.is_some() => st.last_failure = Some(e),
            Err(e) => st.last_failure = Some(err("revocation_unavailable", format!("revocation fetch failed: {}", e.message))),
        }
    }

    fn with_usable<T>(&self, st: &Cache<Snapshot>, f: impl FnOnce(&Snapshot) -> T) -> Result<T, SpiffeError> {
        match &st.good {
            Some((s, at)) if { let age = (self.now)() - at; age.is_finite() && age <= self.max_stale_ms } => Ok(f(s)),
            _ => Err(st.last_failure.clone().unwrap_or_else(|| err("revocation_unavailable", "no revocation snapshot available"))),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache<Snapshot>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Fetch now; refuses with the failure when it fails (the last good snapshot is kept for later checks).
    pub fn refresh(&self) -> Result<(), SpiffeError> {
        let mut st = self.lock();
        self.run(&mut st);
        st.last_failure.clone().map_or(Ok(()), Err)
    }

    /// Refetch when the snapshot is `refresh_ms` old (or absent), then require a usable one.
    pub fn ensure_fresh(&self) -> Result<(), SpiffeError> {
        let mut st = self.lock();
        if st.good.as_ref().is_none_or(|(_, at)| !((self.now)() - at < self.refresh_ms)) {
            self.run(&mut st);
        }
        self.with_usable(&st, |_| ())
    }

    /// Is this certificate (`{spiffeId, serialNumber, fingerprint256, ...}`) revoked?
    pub fn x509(&self, s: &Value) -> Result<bool, SpiffeError> {
        let st = self.lock();
        let g = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        self.with_usable(&st, |snap| {
            snap.fingerprints.contains(&norm_hex(&g("fingerprint256")))
                || snap.serials.contains(&norm_serial(&g("serialNumber")))
                || snap.spiffe_ids.contains(&g("spiffeId"))
        })
    }

    /// Is this JWT-SVID (`{spiffeId, jti?, expiresAt, tokenHash}`) revoked? Refreshes first.
    pub fn jwt(&self, s: &Value) -> Result<bool, SpiffeError> {
        self.ensure_fresh()?;
        let st = self.lock();
        let g = |k: &str| s.get(k).and_then(Value::as_str).map(String::from);
        self.with_usable(&st, |snap| {
            g("spiffeId").is_some_and(|x| snap.spiffe_ids.contains(&x))
                || g("jti").is_some_and(|x| snap.jtis.contains(&x))
                || g("tokenHash").is_some_and(|x| snap.token_hashes.contains(&x))
        })
    }

    /// This source as a [`verify_x509_svid`] revocation check.
    pub fn x509_check(&self) -> impl Fn(&Value) -> Result<Value, String> + '_ {
        move |s| self.x509(s).map(Value::Bool).map_err(|e| e.message)
    }

    /// This source as a [`verify_jwt_svid`] revocation check.
    pub fn jwt_check(&self) -> impl Fn(&Value) -> Result<Value, String> + '_ {
        move |s| self.jwt(s).map(Value::Bool).map_err(|e| e.message)
    }
}
