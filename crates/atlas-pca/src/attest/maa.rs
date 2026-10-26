//! Microsoft Azure Attestation (MAA) tokens: the signing `x5c` chain anchored in a configured root, the ES256 / RS256
//! signature, the `iss` and time claims and the `sevsnpvm` / `tdxvm` isolation claims with their policy gates.

use super::der::x509_valid_at;
use super::jws::{decode_claim_bytes, js_str, num_claim, parse_jws, transform_binding, Jws};
use super::util::{b64_lenient, first_string, lower_list, str_array, timing_safe_eq};
use super::x509::{rsa_pkcs1_verify, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use super::{attestation_binding, default_measured, AttResult, Binding};
use serde_json::{Map, Value};

const SEVSNP_MEASUREMENT_KEYS: [&str; 1] = ["x-ms-sevsnpvm-launchmeasurement"];
const SEVSNP_REPORTDATA_KEYS: [&str; 1] = ["x-ms-sevsnpvm-reportdata"];
const SEVSNP_HOSTDATA_KEYS: [&str; 1] = ["x-ms-sevsnpvm-hostdata"];
const SEVSNP_DEBUG_KEY: &str = "x-ms-sevsnpvm-is-debuggable";
static SEVSNP_TCB_CLAIMS: [(&str, &str, &str); 4] = [
    ("bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"),
    ("snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"),
    ("microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"),
    ("tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"),
];
const TDX_MRTD_KEYS: [&str; 2] = ["tdx_mrtd", "x-ms-tdx-mrtd"];
const TDX_REPORTDATA_KEYS: [&str; 3] = ["tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata"];
const TDX_RTMR0_KEYS: [&str; 2] = ["tdx_rtmr0", "x-ms-tdx-rtmr0"];

#[derive(Clone, Debug, Default)]
pub struct MaaAnchors {
    pub root_certs_pem: Vec<String>,
    pub root_spki_sha256: Vec<String>,
}

/// An `x5c` array entry: `None` for a non-string element.
pub type X5c = Vec<Option<String>>;

pub fn x5c_of(v: &Value) -> Option<X5c> {
    let a = v.as_array()?;
    Some(a.iter().map(|x| x.as_str().map(|s| s.to_string())).collect())
}

fn wrap_x5c(e: String) -> String {
    format!("x5c chain verification error (fail closed): {e}")
}

/// A certificate given as PEM text (a `CERTIFICATE` block).
pub fn cert_from_pem_text(pem: &str) -> Result<Cert, String> {
    match super::x509::pem_blocks(pem).first() {
        Some(b) => Cert::from_pem(b),
        None => Err("error:1E08010C:DECODER routines::unsupported".to_string()),
    }
}

/// `verifyX5cChain`: the leaf certificate of a chain anchored in a configured root. `Err` is the failure reason.
pub fn verify_x5c_chain(x5c: &X5c, anchors: &MaaAnchors, now_ms: f64, skew_ms: f64) -> Result<Cert, String> {
    if x5c.is_empty() {
        return Err("empty x5c certificate chain".into());
    }
    let skew = if skew_ms.is_finite() { skew_ms.max(0.0) } else { 0.0 };
    let mut certs: Vec<Cert> = Vec::new();
    for (i, e) in x5c.iter().enumerate() {
        let b64 = match e {
            Some(s) if !s.is_empty() => s,
            _ => return Err(format!("empty x5c entry at index {i}")),
        };
        let cert = Cert::from_der(&b64_lenient(b64)).map_err(|m| format!("malformed x5c certificate at index {i}: {m}"))?;
        if !x509_valid_at(&cert.raw, now_ms, skew) {
            return Err(format!("x5c certificate at index {i} is outside its validity window"));
        }
        certs.push(cert);
    }
    let mut fingerprints: Vec<String> = Vec::new();
    for fp in &anchors.root_spki_sha256 {
        if !fp.is_empty() {
            fingerprints.push(fp.to_lowercase());
        }
    }
    let mut root_keys: Vec<PubKey> = Vec::new();
    for pem in &anchors.root_certs_pem {
        let c = cert_from_pem_text(pem).map_err(wrap_x5c)?;
        let k = c.public_key().map_err(wrap_x5c)?;
        fingerprints.push(k.spki_sha256_hex());
        root_keys.push(k);
    }
    if fingerprints.is_empty() && root_keys.is_empty() {
        return Err("no MAA trust anchor configured (fail closed)".into());
    }
    let mut keys: Vec<PubKey> = Vec::new();
    for c in &certs {
        keys.push(c.public_key().map_err(wrap_x5c)?);
    }
    let anchor_idx = (0..certs.len()).find(|j| fingerprints.contains(&keys[*j].spki_sha256_hex()));
    if let Some(a) = anchor_idx {
        for i in 0..a {
            if !certs[i].verify(&keys[i + 1]) {
                return Err(format!("x5c link {i} is not signed by the certificate above it"));
            }
        }
        return Ok(certs[0].clone());
    }
    for i in 0..certs.len() - 1 {
        if !certs[i].verify(&keys[i + 1]) {
            return Err(format!("x5c link {i} is not signed by the certificate above it"));
        }
    }
    let top = &certs[certs.len() - 1];
    if !root_keys.iter().any(|k| top.verify(k)) {
        return Err("x5c chain does not anchor in a configured MAA trust root".into());
    }
    Ok(certs[0].clone())
}

fn verify_jws_signature(parsed: &Jws, leaf: &Cert) -> Result<(), String> {
    let key = leaf.public_key()?;
    if parsed.alg == "ES256" {
        let is_p256 = matches!(&key, PubKey::Ec { curve, .. } if *curve == EcCurve::P256);
        if !is_p256 {
            return Err(format!("ES256 token but signing key is {}/{} (not EC P-256)", key.jwk_kty(), key.jwk_crv()));
        }
        if parsed.signature.len() != 64 {
            return Err(format!("ES256 signature is {} bytes (expected 64: r\u{2016}s)", parsed.signature.len()));
        }
        if verify_p1363_sig(&key, Hash::Sha256, &parsed.signing_input, &parsed.signature) {
            return Ok(());
        }
        return Err("JWS ES256 signature does not verify under the MAA signing key".into());
    }
    if parsed.alg == "RS256" {
        return match &key {
            PubKey::Rsa { n, e } => {
                if rsa_pkcs1_verify(n, e, Hash::Sha256, &parsed.signing_input, &parsed.signature) {
                    Ok(())
                } else {
                    Err("JWS RS256 signature does not verify under the MAA signing key".into())
                }
            }
            other => Err(format!("RS256 token but signing key is {} (not RSA)", other.jwk_kty())),
        };
    }
    Err(format!("unsupported JWS alg '{}' (MAA uses ES256 / RS256)", parsed.alg))
}

/// The signing `x5c` chain: the JWKS entry matched by `kid`, else the header's own.
fn resolve_signing_x5c(header_kid: &Option<String>, header_x5c: &Option<Vec<String>>, jwks: Option<&Value>) -> Result<X5c, String> {
    let keys = jwks.and_then(|j| j.get("keys")).and_then(Value::as_array);
    if let Some(keys) = keys.filter(|k| !k.is_empty()) {
        let key_x5c = |k: &Value| -> Option<X5c> { k.get("x5c").and_then(x5c_of).filter(|x| !x.is_empty()) };
        let kid = match header_kid {
            Some(k) if !k.is_empty() => k.clone(),
            _ => {
                if keys.len() != 1 {
                    return Err("token has no kid and the JWKS publishes multiple keys (ambiguous)".into());
                }
                return key_x5c(&keys[0]).ok_or_else(|| "JWKS key carries no x5c chain".to_string());
            }
        };
        let m = match keys.iter().find(|k| k.get("kid").and_then(Value::as_str) == Some(kid.as_str())) {
            Some(m) => m,
            None => return Err(format!("no JWKS key matches the token kid '{kid}' (untrusted signer)")),
        };
        return key_x5c(m).ok_or_else(|| format!("JWKS key '{kid}' carries no x5c chain"));
    }
    match header_x5c {
        Some(x) if !x.is_empty() => Ok(x.iter().map(|s| Some(s.clone())).collect()),
        _ => Err("no signing x5c available (no JWKS and no header x5c)".into()),
    }
}

#[derive(Clone, Debug, Default)]
pub struct MaaPolicy {
    pub sev_snp_measurements: Vec<String>,
    pub tdx_mrtds: Vec<String>,
    pub sev_snp_host_data: Vec<String>,
    pub tdx_rtmrs: Vec<String>,
    /// (policy name, claim key, host key, floor)
    pub min_tcb: Vec<(&'static str, &'static str, &'static str, f64)>,
    pub allow_debug: bool,
    pub runtime_user_data_binding: bool,
    pub tdx_allowed_tcb_statuses: Option<Vec<String>>,
    pub report_data_hash: Option<String>,
}

pub struct MaaVerifier {
    trusted_issuers: Vec<String>,
    anchors: MaaAnchors,
    policy: MaaPolicy,
    skew: f64,
}

impl MaaVerifier {
    pub fn from_config(cfg: &Map<String, Value>) -> Result<MaaVerifier, String> {
        let pre = "createAzureMaaVerifier";
        let issuers = match cfg.get("trustedIssuers").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => a,
            _ => return Err(format!("{pre}: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")),
        };
        let mut trusted_issuers = Vec::new();
        for i in issuers {
            match i.as_str() {
                Some(s) if !s.is_empty() => trusted_issuers.push(s.to_string()),
                _ => return Err(format!("{pre}: every trusted issuer must be a non-empty URL string")),
            }
        }
        let empty = Map::new();
        let ta = cfg.get("trustAnchors").and_then(Value::as_object).unwrap_or(&empty);
        let anchors = MaaAnchors {
            root_certs_pem: ta.get("rootCertsPem").and_then(str_array).unwrap_or_default(),
            root_spki_sha256: ta.get("rootSpkiSha256").and_then(str_array).unwrap_or_default(),
        };
        let count = ta.get("rootCertsPem").and_then(Value::as_array).map_or(0, |a| a.len()) + ta.get("rootSpkiSha256").and_then(Value::as_array).map_or(0, |a| a.len());
        if count == 0 {
            return Err(format!("{pre}: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) \u{2014} accept-all is not permitted"));
        }
        let pol = cfg.get("policy").and_then(Value::as_object);
        let list = |k: &str| -> Vec<String> { pol.and_then(|p| p.get(k)).and_then(str_array).map(|v| lower_list(&v)).unwrap_or_default() };
        let sev = list("sevSnpMeasurements");
        let tdx = list("tdxMrtds");
        if pol.is_none() || (sev.is_empty() && tdx.is_empty()) {
            return Err(format!("{pre}: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)"));
        }
        let pol = pol.unwrap_or(&empty);
        let mut min_tcb = Vec::new();
        if let Some(m) = pol.get("sevSnpMinTcb") {
            let m = match m.as_object() {
                Some(o) => o,
                None => return Err(format!("{pre}: policy.sevSnpMinTcb must be an object")),
            };
            for (k, v) in m {
                let known = SEVSNP_TCB_CLAIMS.iter().find(|c| c.0 == k.as_str());
                let known = match known {
                    Some(c) => c,
                    None => return Err(format!("{pre}: policy.sevSnpMinTcb.{k} is not a known field (bootloader | snp | microcode | tee)")),
                };
                match v.as_f64() {
                    Some(n) if n.fract() == 0.0 && n >= 0.0 => min_tcb.push((known.0, known.1, known.2, n)),
                    _ => return Err(format!("{pre}: policy.sevSnpMinTcb.{k} must be a non-negative integer")),
                }
            }
        }
        let policy = MaaPolicy {
            sev_snp_measurements: sev,
            tdx_mrtds: tdx,
            sev_snp_host_data: list("sevSnpHostData"),
            tdx_rtmrs: list("tdxRtmrs"),
            min_tcb,
            allow_debug: pol.get("allowDebug").and_then(Value::as_bool) == Some(true),
            runtime_user_data_binding: pol.get("runtimeUserDataBinding").and_then(Value::as_bool) == Some(true),
            tdx_allowed_tcb_statuses: pol.get("tdxAllowedTcbStatuses").and_then(str_array),
            report_data_hash: pol.get("reportDataHash").and_then(Value::as_str).map(|s| s.to_string()),
        };
        let skew = cfg.get("clockSkewMs").and_then(Value::as_f64).map_or(0.0, |s| s.max(0.0));
        Ok(MaaVerifier { trusted_issuers, anchors, policy, skew })
    }

    pub fn verify(&self, ev: Option<&Value>, now_ms: i64, expected: Option<&Binding>) -> AttResult {
        let token = match ev.and_then(|e| e.get("token")).and_then(Value::as_str) {
            Some(t) if !t.is_empty() => t,
            _ => return AttResult::fail("no Azure MAA token for this action"),
        };
        let jwks = ev.and_then(|e| e.get("jwks"));
        let parsed = match parse_jws(token, "parseMaaJwt") {
            Ok(p) => p,
            Err(e) => return AttResult::fail(format!("MAA token parse failed: {e}")),
        };
        if parsed.alg != "ES256" && parsed.alg != "RS256" {
            return AttResult::fail(format!("unsupported JWS alg '{}' (MAA uses ES256 / RS256)", parsed.alg));
        }
        let now = now_ms as f64;
        let x5c = match resolve_signing_x5c(&parsed.kid, &parsed.x5c, jwks) {
            Ok(x) => x,
            Err(r) => return AttResult::fail(r),
        };
        let leaf = match verify_x5c_chain(&x5c, &self.anchors, now, self.skew) {
            Ok(l) => l,
            Err(r) => return AttResult::fail(format!("MAA signing chain invalid: {r}")),
        };
        if let Err(e) = verify_jws_signature(&parsed, &leaf) {
            return AttResult::fail(e);
        }
        let p = &parsed.payload;
        let iss = p.get("iss").and_then(Value::as_str);
        match iss {
            Some(i) if !i.is_empty() && self.trusted_issuers.iter().any(|t| t == i) => {}
            _ => return AttResult::fail(format!("token iss '{}' is not a configured trusted MAA instance", js_str(iss))),
        }
        let now_sec = (now / 1000.0).floor();
        let skew_sec = (self.skew / 1000.0).ceil();
        let (exp, iat, nbf) = (num_claim(p, "exp"), num_claim(p, "iat"), num_claim(p, "nbf"));
        let exp = match exp {
            Some(e) => e,
            None => return AttResult::fail("token has no exp (cannot bound validity \u{2014} fail closed)"),
        };
        if now_sec - skew_sec > exp {
            return AttResult::fail("MAA token expired");
        }
        if let Some(n) = nbf {
            if now_sec + skew_sec < n {
                return AttResult::fail("MAA token not yet valid (nbf)");
            }
        }
        if let Some(i) = iat {
            if now_sec + skew_sec < i {
                return AttResult::fail("MAA token issued in the future (iat)");
            }
        }
        let tee: &Map<String, Value> = p.get("x-ms-isolation-tee").and_then(Value::as_object).unwrap_or(p);
        let itype = tee.get("x-ms-attestation-type").and_then(Value::as_str).or_else(|| p.get("x-ms-attestation-type").and_then(Value::as_str));
        let is_snp = itype == Some("sevsnpvm");
        if !is_snp && itype != Some("tdxvm") {
            return AttResult::fail(format!("unexpected x-ms-attestation-type '{}' (expected sevsnpvm | tdxvm)", js_str(itype)));
        }
        let expected = match expected {
            Some(e) => e,
            None => return AttResult::fail("no expected attestation binding supplied"),
        };
        if self.policy.runtime_user_data_binding {
            let raw = match attestation_binding(expected) {
                Ok(b) => b,
                Err(e) => return AttResult::fail(format!("binding not constructible: {e}")),
            };
            let runtime = match p.get("x-ms-runtime").and_then(Value::as_object) {
                Some(r) => r,
                None => return AttResult::fail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)"),
            };
            let ud = match runtime.get("user-data").and_then(Value::as_str) {
                Some(u) if !u.is_empty() => u,
                _ => return AttResult::fail("x-ms-runtime carries no user-data to bind the PCA challenge"),
            };
            match decode_claim_bytes(ud) {
                Some(b) if timing_safe_eq(&b, &raw) => {}
                _ => return AttResult::fail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)"),
            }
        } else {
            let binding_bytes = match attestation_binding(expected) {
                Ok(b) => transform_binding(&b, self.policy.report_data_hash.as_deref()),
                Err(e) => return AttResult::fail(format!("binding not constructible: {e}")),
            };
            let keys: &[&str] = if is_snp { &SEVSNP_REPORTDATA_KEYS } else { &TDX_REPORTDATA_KEYS };
            let claim = match first_string(tee, keys) {
                Some(c) => c,
                None => return AttResult::fail("token carries no report-data claim to bind the PCA challenge"),
            };
            let bytes = match decode_claim_bytes(claim) {
                Some(b) => b,
                None => return AttResult::fail("report-data claim is not decodable (hex/base64)"),
            };
            if !timing_safe_eq(&bytes, &binding_bytes) {
                return AttResult::fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)");
            }
        }
        if is_snp {
            self.verify_snp(tee)
        } else {
            self.verify_tdx(tee)
        }
    }

    fn verify_snp(&self, tee: &Map<String, Value>) -> AttResult {
        let pol = &self.policy;
        if pol.sev_snp_measurements.is_empty() {
            return AttResult::fail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)");
        }
        let m = match first_string(tee, &SEVSNP_MEASUREMENT_KEYS) {
            Some(m) => m,
            None => return AttResult::fail("sevsnpvm token carries no launch-measurement claim"),
        };
        let m_hex = m.to_lowercase();
        if !pol.sev_snp_measurements.contains(&m_hex) {
            return AttResult::fail("SEV-SNP launch measurement not in policy allowlist");
        }
        if !pol.allow_debug && tee.get(SEVSNP_DEBUG_KEY).and_then(Value::as_bool) == Some(true) {
            return AttResult::fail("SEV-SNP guest is debuggable (no confidentiality)");
        }
        let host_data = first_string(tee, &SEVSNP_HOSTDATA_KEYS);
        if !pol.sev_snp_host_data.is_empty() {
            match host_data {
                Some(h) if pol.sev_snp_host_data.contains(&h.to_lowercase()) => {}
                _ => return AttResult::fail("SEV-SNP host-data not in policy allowlist"),
            }
        }
        let mut reported: Vec<(&str, String)> = Vec::new();
        for (name, claim, host_key) in SEVSNP_TCB_CLAIMS.iter() {
            let raw = tee.get(*claim).and_then(Value::as_f64);
            let svn = raw.filter(|n| n.fract() == 0.0 && *n >= 0.0);
            if let Some(n) = svn {
                reported.push((*host_key, super::snp::js_num(n)));
            }
            let floor = pol.min_tcb.iter().find(|f| f.0 == *name).map(|f| f.3);
            let floor = match floor {
                Some(f) => f,
                None => continue,
            };
            let n = match svn {
                Some(n) => n,
                None => return AttResult::fail(format!("SEV-SNP {name} SVN claim '{claim}' is missing or not a non-negative integer (policy requires a minimum)")),
            };
            if n < floor {
                return AttResult::fail(format!("SEV-SNP {name} SVN {} is below the policy minimum {}", super::snp::js_num(n), super::snp::js_num(floor)));
            }
        }
        let mut host: Vec<(&str, String)> = vec![("attestation_type", "sevsnpvm".to_string())];
        host.extend(reported);
        if let Some(h) = host_data {
            host.push(("host_data", h.to_lowercase()));
        }
        AttResult::pass(default_measured(&m_hex, ""), host)
    }

    fn verify_tdx(&self, tee: &Map<String, Value>) -> AttResult {
        let pol = &self.policy;
        if pol.tdx_mrtds.is_empty() {
            return AttResult::fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)");
        }
        let mrtd = match first_string(tee, &TDX_MRTD_KEYS) {
            Some(m) => m,
            None => return AttResult::fail("tdxvm token carries no MRTD claim"),
        };
        let mrtd_hex = mrtd.to_lowercase();
        if !pol.tdx_mrtds.contains(&mrtd_hex) {
            return AttResult::fail("TDX MRTD not in policy allowlist");
        }
        let td_debug = tee.get("tdx_td_attributes_debug").and_then(Value::as_bool);
        let dbgstat = tee.get("dbgstat").and_then(Value::as_str);
        if !pol.allow_debug && (td_debug == Some(true) || dbgstat.map_or(false, |d| d != "disabled")) {
            return AttResult::fail("TDX guest is debuggable (no confidentiality)");
        }
        let tcb_status = tee.get("attester_tcb_status").and_then(Value::as_str);
        if let Some(s) = tcb_status {
            let default_ok = ["UpToDate".to_string(), "SWHardeningNeeded".to_string()];
            let ok = match &pol.tdx_allowed_tcb_statuses {
                Some(v) => v.iter().any(|x| x == s),
                None => default_ok.iter().any(|x| x == s),
            };
            if !ok {
                return AttResult::fail(format!("TDX platform TCB status '{s}' is not accepted by policy"));
            }
        }
        let rtmr0 = first_string(tee, &TDX_RTMR0_KEYS);
        if !pol.tdx_rtmrs.is_empty() {
            match rtmr0 {
                Some(r) if pol.tdx_rtmrs.contains(&r.to_lowercase()) => {}
                _ => return AttResult::fail("TDX RTMR0 not in policy allowlist"),
            }
        }
        let mut host: Vec<(&str, String)> = vec![("attestation_type", "tdxvm".to_string())];
        if let Some(s) = tcb_status {
            if !s.is_empty() {
                host.push(("tcb_status", s.to_string()));
            }
        }
        if let Some(r) = rtmr0 {
            host.push(("rtmr0", r.to_lowercase()));
        }
        AttResult::pass(default_measured(&mrtd_hex, ""), host)
    }
}
