//! The reference's public names for the small parts of the hardware-attestation modules that sit beside the verifiers: the suite labels and
//! the default accepted TCB statuses, the Azure Attestation / Confidential Space JWT parsers and JWKS fetchers (over an injected
//! transport: nothing here ever opens a connection by itself), the PCS issuer-chain header decoder, the TD report reader, the P-256 key
//! reader and the default `tpm2-tools` runner.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::jws::{parse_jws, Jws};
use super::puf::TpmCommandResult;

/// The suite label of the Intel TDX DCAP verifier.
pub const INTEL_DCAP_SUITE: &str = "intel-tdx-dcap-ecdsa-p256";
/// The signature suites a Microsoft Azure Attestation instance signs its JWTs with today (both classical).
pub const AZURE_MAA_SUITES: [&str; 2] = ["ES256", "RS256"];
/// The audit label of the Azure Attestation root's suite family.
pub const AZURE_MAA_SUITE: &str = "azure-maa-jwt";
/// The signature suites a Google Confidential Space attestation token is signed with today (both classical).
pub const GCP_CS_SUITES: [&str; 2] = ["RS256", "ES256"];
/// The audit label of the Confidential Space root's suite family.
pub const GCP_CS_SUITE: &str = "gcp-confidential-space-jwt";
/// The Intel TCB statuses the collateral policy accepts unless told otherwise.
pub const DEFAULT_ACCEPTED_STATUSES: [&str; 2] = ["UpToDate", "SWHardeningNeeded"];
/// The SHA-256 (lowercase hex) of the SPKI of the Intel SGX Root CA every PCK chain must end in.
pub use super::dcap::INTEL_SGX_ROOT_CA_SPKI_SHA256;
/// The audit label of the AMD SEV-SNP verifier.
pub use super::snp::AMD_SNP_SUITE;
/// The issuer of Google Confidential Space attestation tokens.
pub use super::gcp::GCP_CS_DEFAULT_ISSUER;

/// `AMD_ARK_SPKI_SHA384`: the SPKI SHA-384 (lowercase hex) of each family's ARK, `{milan, genoa, turin}`.
pub fn amd_ark_spki_sha384() -> Value {
    let mut m = Map::new();
    for f in ["milan", "genoa", "turin"] {
        if let Some(p) = super::snp::ark_pin(f) {
            m.insert(f.into(), json!(p));
        }
    }
    Value::Object(m)
}

/// `toHex`: lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    super::util::hex_lower(bytes)
}

/// `pemToDer`: the bytes of the FIRST certificate block (base64 body, whitespace removed, decoded as Node's lenient base64). `Err` when
/// there is no block or its body is empty.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    const B: &str = "-----BEGIN CERTIFICATE-----";
    const E: &str = "-----END CERTIFICATE-----";
    let body = super::x509::pem_blocks(pem).first().and_then(|b| b.strip_prefix(B)).and_then(|b| b.strip_suffix(E)).filter(|b| !b.is_empty());
    match body {
        Some(b) => Ok(super::util::b64_lenient(&b.chars().filter(|c| !c.is_whitespace()).collect::<String>())),
        None => Err("pemToDer: no certificate found".into()),
    }
}

/// `parseMaaJwt`: a compact JWS Azure Attestation token into its header fields, claims, signing input and signature. `Err` on a structurally
/// invalid token; nothing is verified.
pub fn parse_maa_jwt(token: &str) -> Result<Jws, String> {
    parse_jws(token, "parseMaaJwt")
}

/// `parseGcpCsJwt`: the same for a Confidential Space token.
pub fn parse_gcp_cs_jwt(token: &str) -> Result<Jws, String> {
    parse_jws(token, "parseGcpCsJwt")
}

/// An injected HTTP GET: `(status, body)` for a URL. `Err` is a transport failure.
pub type JwksFetch<'a> = &'a dyn Fn(&str) -> Result<(u16, String), String>;

fn trim_slashes(s: &str) -> &str {
    s.trim_end_matches('/')
}

/// The members of one JWK a verifier reads: each of `members` when it is a string, and `x5c` when it is a list of strings.
fn keep_jwk(k: &Value, members: &[&str]) -> Option<Value> {
    let k = k.as_object()?;
    let mut o = Map::new();
    for m in members {
        if let Some(s) = k.get(*m).filter(|v| v.is_string()) {
            o.insert((*m).into(), s.clone());
        }
    }
    if let Some(a) = k.get("x5c").and_then(Value::as_array).filter(|a| a.iter().all(Value::is_string)) {
        o.insert("x5c".into(), Value::Array(a.clone()));
    }
    Some(Value::Object(o))
}

fn fetch_jwks(what: &str, url: &str, fetch: JwksFetch<'_>, members: &[&str]) -> Result<Value, String> {
    let (status, body) = fetch(url)?;
    if !(200..=299).contains(&status) {
        return Err(format!("{what} fetch failed: HTTP {status} for {url}"));
    }
    let doc: Value = serde_json::from_str(body.strip_prefix('\u{feff}').unwrap_or(&body)).map_err(|e| e.to_string())?;
    let keys = doc.get("keys").and_then(Value::as_array).ok_or_else(|| format!("{what} fetch: response has no keys array"))?;
    Ok(json!({"keys": keys.iter().filter_map(|k| keep_jwk(k, members)).collect::<Vec<_>>()}))
}

/// `fetchMaaJwks`: an Azure Attestation instance's JWKS from `<issuer><certs_path or "/certs">` (NETWORK I/O through `fetch`, never invoked on
/// its own): `{keys: [{kid?, kty?, alg?, x5c?}]}`.
pub fn fetch_maa_jwks(issuer: &str, fetch: JwksFetch<'_>, certs_path: Option<&str>) -> Result<Value, String> {
    let url = format!("{}{}", trim_slashes(issuer), certs_path.unwrap_or("/certs"));
    fetch_jwks("MAA JWKS", &url, fetch, &["kid", "kty", "alg"])
}

/// `fetchGcpConfidentialSpaceJwks`: the Google attestation issuer's JWKS. Resolves `<issuer>/.well-known/openid-configuration` to its
/// `jwks_uri` unless `jwks_uri` is given. `{keys: [{kid?, kty?, alg?, use?, n?, e?, crv?, x?, y?, x5c?}]}`.
pub fn fetch_gcp_confidential_space_jwks(issuer: &str, fetch: JwksFetch<'_>, jwks_uri: Option<&str>) -> Result<Value, String> {
    let uri = match jwks_uri.filter(|u| !u.is_empty()) {
        Some(u) => u.to_string(),
        None => {
            let conf_url = format!("{}/.well-known/openid-configuration", trim_slashes(issuer));
            let (status, body) = fetch(&conf_url)?;
            if !(200..=299).contains(&status) {
                return Err(format!("Confidential Space OpenID config fetch failed: HTTP {status} for {conf_url}"));
            }
            let conf: Value = serde_json::from_str(body.strip_prefix('\u{feff}').unwrap_or(&body)).map_err(|e| e.to_string())?;
            match conf.get("jwks_uri").and_then(Value::as_str).filter(|u| !u.is_empty()) {
                Some(u) => u.to_string(),
                None => return Err("Confidential Space OpenID config carries no jwks_uri".into()),
            }
        }
    };
    fetch_jwks("Confidential Space JWKS", &uri, fetch, &["kid", "kty", "alg", "use", "n", "e", "crv", "x", "y"])
}

/// `decodeIssuerChainHeader`: a PCS issuer-chain HTTP header value (URL-encoded PEM) as PEM (`decodeURIComponent`). `Err` for a malformed
/// escape or an escape that is not UTF-8.
pub fn decode_issuer_chain_header(value: &str) -> Result<String, String> {
    let b = value.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let hex = |o: usize| b.get(o).and_then(|c| (*c as char).to_digit(16));
        match (hex(i + 1), hex(i + 2)) {
            (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
            _ => return Err("URI malformed".into()),
        }
        i += 3;
    }
    String::from_utf8(out).map_err(|_| "URI malformed".to_string())
}

/// A parsed genuine TD report (TDX 1.0, "TD10"). Byte fields are copies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapTdReport {
    pub tee_tcb_svn: Vec<u8>,
    pub mr_seam: Vec<u8>,
    pub mr_signer_seam: Vec<u8>,
    /// TD_ATTRIBUTES; bit 0 (byte 0, LSB) is DEBUG.
    pub td_attributes: Vec<u8>,
    pub mr_td: Vec<u8>,
    pub mr_config_id: Vec<u8>,
    pub rtmr0: Vec<u8>,
    pub rtmr1: Vec<u8>,
    pub rtmr2: Vec<u8>,
    pub rtmr3: Vec<u8>,
    pub report_data: Vec<u8>,
    pub raw: Vec<u8>,
}

/// The length of a TD report body.
pub const TD_REPORT_LEN: usize = 584;

/// `parseDcapTdReport`: a genuine 584-byte TD10 report body. `Err` when it is shorter.
pub fn parse_dcap_td_report(body: &[u8]) -> Result<DcapTdReport, String> {
    if body.len() < TD_REPORT_LEN {
        return Err(format!("parseDcapTdReport: body too short ({} < {TD_REPORT_LEN})", body.len()));
    }
    let at = |off: usize, len: usize| body[off..off + len].to_vec();
    Ok(DcapTdReport {
        tee_tcb_svn: at(0, 16),
        mr_seam: at(16, 48),
        mr_signer_seam: at(64, 48),
        td_attributes: at(120, 8),
        mr_td: at(136, 48),
        mr_config_id: at(184, 48),
        rtmr0: at(328, 48),
        rtmr1: at(376, 48),
        rtmr2: at(424, 48),
        rtmr3: at(472, 48),
        report_data: at(520, 64),
        raw: body[..TD_REPORT_LEN].to_vec(),
    })
}

/// `ecdsaP256PublicKey`: a P-256 public key (compressed or uncompressed SEC1) as the uncompressed point (`0x04 || X || Y`, 65 bytes).
/// `Err` for anything that is not a point on the curve.
pub fn ecdsa_p256_public_key(sec1: &[u8]) -> Result<Vec<u8>, String> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).map_err(|e| e.to_string())?;
    Ok(vk.to_encoded_point(false).as_bytes().to_vec())
}

/// `defaultTpmCommandRunner`: spawns the `tpm2-tools` binary and waits for it (15 s, 1 MiB of output). Never fails for a tool or TPM
/// failure: a non-zero exit is its status, a spawn failure (not installed, not executable), a timeout or an over-long output is
/// `status: None` with `error` set, so the provider fails closed.
pub fn default_tpm_command_runner(command: &str, args: &[String]) -> TpmCommandResult {
    const MAX: usize = 1 << 20;
    let failed = |why: String| TpmCommandResult { status: None, stdout: Some(Vec::new()), stderr: None, error: Some(format!("{command}: {why}")) };
    let mut child = match Command::new(command).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(e) => return failed(e.kind().to_string()),
    };
    let reader = |s: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(s) = s {
                let _ = s.take(MAX as u64 + 1).read_to_end(&mut buf);
            }
            buf
        })
    };
    let out = reader(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let err = reader(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return failed("ETIMEDOUT".into());
            }
            Err(e) => return failed(e.kind().to_string()),
        }
    };
    let (stdout, stderr) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    if stdout.len() > MAX {
        return failed("ENOBUFS".into());
    }
    let stderr = (!stderr.is_empty()).then(|| String::from_utf8_lossy(&stderr).into_owned());
    match status.code() {
        Some(c) => TpmCommandResult { status: Some(i64::from(c)), stdout: Some(stdout), stderr, error: None },
        None => TpmCommandResult { status: None, stdout: Some(stdout), stderr, error: Some(format!("{command}: signalled")) },
    }
}
