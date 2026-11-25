//! The pure AMD SEV-SNP helpers of `hardware-sevsnp.ts` that need neither AMD hardware nor a certificate chain: the hex helper, PEM
//! splitting, the P-384 key and signature primitives, the report signature check, the VCEK certificate readers, the default identity
//! derivation and the AMD KDS VCEK fetch over an INJECTED transport. The report parser, the policy gate and the VCEK / report binding live
//! in [`super::snp`] (the typed [`SnpReport`] and [`SnpPolicy`]); the chain and genuine-report verifiers are exercised by the vendor
//! evidence replays.
use serde_json::{json, Value};

use super::der::tbs_of_certificate;
use super::snp::{report_sig_valid, SnpReport};
use super::util::hex_lower;
use super::x509::{parse_spki, pem_blocks, Cert, EcCurve, PubKey};

/// The SIGNATURE_ALGO value for ECDSA over P-384 with SHA-384 (the only algorithm SEV-SNP uses today).
pub const SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
/// SEV-SNP guest POLICY bit 19: DEBUG (the host may read and modify guest memory: no confidentiality).
pub const SEV_SNP_POLICY_DEBUG_BIT: u64 = 1 << 19;
/// The AMD SEV Milan ARK trust anchor: the SHA-384 of its DER SubjectPublicKeyInfo (lowercase hex).
pub const AMD_MILAN_ARK_SPKI_SHA384: &str =
    "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e";

/// The order of the NIST P-384 group, big endian.
const P384_ORDER: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a,
    0xcc, 0xc5, 0x29, 0x73,
];

/// Lowercase hex of a byte array (the stable identity string of a measurement, chip id or host data).
pub fn to_hex(bytes: &[u8]) -> String {
    hex_lower(bytes)
}

/// Split a PEM bundle into its `-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----` blocks, text unchanged.
pub fn split_pem_certificates(pem: &str) -> Vec<String> {
    pem_blocks(pem).into_iter().map(str::to_string).collect()
}

/// Validate a P-384 public key and return it as the uncompressed SEC1 point (`0x04 || X(48) || Y(48)`, 97 bytes). Accepts the
/// uncompressed or the compressed (49-byte) encoding; `Err` for anything that is not a point on the curve.
pub fn ecdsa_p384_public_key(sec1: &[u8]) -> Result<Vec<u8>, String> {
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(sec1).map_err(|e| e.to_string())?;
    Ok(vk.to_encoded_point(false).as_bytes().to_vec())
}

/// The value of a little-endian byte array as 48 big-endian bytes, or `None` when it needs more than 48 (it is then above the group order).
fn le_to_be48(le: &[u8]) -> Option<[u8; 48]> {
    if le.iter().skip(48).any(|b| *b != 0) {
        return None;
    }
    let mut be = [0u8; 48];
    for (i, b) in le.iter().take(48).enumerate() {
        be[47 - i] = *b;
    }
    Some(be)
}

fn scalar_in_range(be: &Option<[u8; 48]>) -> Option<[u8; 48]> {
    be.filter(|b| b.iter().any(|x| *x != 0) && b.as_slice() < P384_ORDER.as_slice())
}

/// AMD's little-endian `r` and `s` (72-byte fields, only the value matters) as the 96-byte big-endian compact `r || s`. `Err` when `r` or
/// `s` is zero or not below the group order (a structurally invalid signature).
pub fn sev_snp_signature_to_compact(r: &[u8], s: &[u8]) -> Result<Vec<u8>, String> {
    let rb = scalar_in_range(&le_to_be48(r)).ok_or("sev-snp signature: r out of range")?;
    let sb = scalar_in_range(&le_to_be48(s)).ok_or("sev-snp signature: s out of range")?;
    Ok([rb, sb].concat())
}

/// Verify the report's ECDSA-P384 / SHA-384 signature over its signed region `[0, 0x2a0)` under the VCEK public key (any SEC1 encoding).
/// Never fails: a malformed signature or key is `false`. A high-S signature is accepted (AMD hardware does not normalise it).
pub fn verify_sev_snp_report_signature(report: &SnpReport, vcek_sec1: &[u8]) -> bool {
    match ecdsa_p384_public_key(vcek_sec1) {
        Ok(point) => report_sig_valid(report, &PubKey::Ec { curve: EcCurve::P384, point }),
        Err(_) => false,
    }
}

/// The default report to measured-identity mapping: `runtime_measurement` is the hex MEASUREMENT (hardware-authoritative), `operator` the
/// hex CHIP_ID, `weights_digest` the host-asserted HOST_DATA ONLY with the insecure `weights_from_host_data` opt-in (else `""`);
/// `weights_measured` is ALWAYS false (SEV-SNP has no weights field) and `model_id` is `""`.
pub fn make_default_derive_identity(report: &SnpReport, weights_from_host_data: bool) -> Value {
    json!({
        "model_id": "",
        "weights_digest": if weights_from_host_data { to_hex(&report.host_data) } else { String::new() },
        "weights_measured": false,
        "runtime_measurement": to_hex(&report.measurement),
        "operator": to_hex(&report.chip_id),
    })
}

/// Decode a VCEK certificate (DER): its EC P-384 public key (the uncompressed SEC1 point, for the report signature check) and its
/// `tbsCertificate` bytes (for the VCEK / report binding). `Err` unless the certificate parses with nothing after it and its key is EC
/// secp384r1.
pub fn extract_vcek_public_key(vcek_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let cert = Cert::from_der(vcek_der)?;
    let point = match parse_spki(&cert.spki)? {
        PubKey::Ec { curve: EcCurve::P384, point } => ecdsa_p384_public_key(&point)?,
        PubKey::Ec { curve, .. } => return Err(format!("VCEK is not EC secp384r1 (got ec/{curve:?})")),
        _ => return Err("VCEK is not EC secp384r1 (got a key that is not EC)".into()),
    };
    Ok((point, extract_tbs_certificate(vcek_der)?))
}

/// The `tbsCertificate` bytes of an X.509 certificate DER: the first inner element of the outer SEQUENCE. `Err` on a structurally invalid
/// certificate or bytes after it.
pub fn extract_tbs_certificate(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    tbs_of_certificate(cert_der)
}

/// The answer of the injected KDS transport.
pub struct KdsResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The KDS URL of the VCEK certificate of a chip at a reported TCB:
/// `<base>/<product>/<chip_id_hex>?blSPL=&teeSPL=&snpSPL=&ucodeSPL=` (SPLs are bytes 0, 1, 6 and 7 of the TCB). `product` defaults to
/// `Milan` and `base_url` to `https://kdsintf.amd.com/vcek/v1`.
pub fn vcek_kds_url(chip_id: &[u8], reported_tcb: u64, product: Option<&str>, base_url: Option<&str>) -> String {
    let byte_at = |i: u32| (reported_tcb >> (8 * i)) & 0xff;
    format!(
        "{}/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        base_url.unwrap_or("https://kdsintf.amd.com/vcek/v1"),
        product.unwrap_or("Milan"),
        to_hex(chip_id),
        byte_at(0),
        byte_at(1),
        byte_at(6),
        byte_at(7)
    )
}

/// Fetch the VCEK certificate (DER) for a live report from AMD's KDS over `fetch` (the transport: a URL in, the status and body out; no
/// default transport is bundled). `Err` without a transport, on a transport failure and on a non-2xx status.
pub fn fetch_vcek_from_kds(
    chip_id: &[u8],
    reported_tcb: u64,
    product: Option<&str>,
    base_url: Option<&str>,
    fetch: Option<&dyn Fn(&str) -> Result<KdsResponse, String>>,
) -> Result<Vec<u8>, String> {
    let Some(fetch) = fetch else { return Err("fetchVcekFromKds: no fetch implementation available".into()) };
    let url = vcek_kds_url(chip_id, reported_tcb, product, base_url);
    let res = fetch(&url)?;
    if !(200..=299).contains(&res.status) {
        return Err(format!("KDS VCEK fetch failed: HTTP {} for {url}", res.status));
    }
    Ok(res.body)
}
