//! Google Cloud Confidential Space tokens: the signing key anchored in a pinned JWKS, a pinned SPKI hash or an `x5c`
//! chain to a configured root, the RS256 / ES256 signature, the `iss` and time claims, the Confidential Space claims
//! (`swname`, `hwmodel`, `dbgstat`, `eat_nonce`) and the image-digest allowlist.

use super::der::x509_valid_at;
use super::jws::{decode_claim_bytes, js_str, num_claim, parse_jws, transform_binding, Jws};
use super::maa::{cert_from_pem_text, x5c_of, X5c};
use super::util::{b64_lenient, lower_list, str_array, timing_safe_eq};
use super::x509::{ec_point_valid, pem_public_key, rsa_pkcs1_verify, verify_p1363_sig, Cert, EcCurve, Hash, PubKey};
use super::{attestation_binding, default_measured, AttResult, Binding};
use serde_json::{Map, Value};

pub const GCP_CS_DEFAULT_ISSUER: &str = "https://confidentialcomputing.googleapis.com";

fn strip_zeros(b: &[u8]) -> Vec<u8> {
    b.iter().copied().skip_while(|x| *x == 0).collect()
}

fn pad_to(b: &[u8], n: usize) -> Option<Vec<u8>> {
    let v = strip_zeros(b);
    if v.len() > n {
        return None;
    }
    let mut out = vec![0u8; n - v.len()];
    out.extend_from_slice(&v);
    Some(out)
}

/// `keyFromJwk`: RSA `n` / `e`, EC `x` / `y`, or the leaf of an `x5c` chain. `Err` is the reason text.
fn key_from_jwk(jwk: &Map<String, Value>) -> Result<PubKey, String> {
    let usable = |e: String| format!("JWKS key is not a usable public key: {e}");
    let s = |k: &str| jwk.get(k).and_then(Value::as_str);
    if let (Some(n), Some(e)) = (s("n"), s("e")) {
        let n = strip_zeros(&b64_lenient(n));
        let e = strip_zeros(&b64_lenient(e));
        if n.is_empty() || e.is_empty() {
            return Err(usable("Invalid JWK RSA key".into()));
        }
        return Ok(PubKey::Rsa { n, e });
    }
    if s("kty") == Some("EC") {
        if let (Some(crv), Some(x), Some(y)) = (s("crv"), s("x"), s("y")) {
            let curve = match crv {
                "P-256" => EcCurve::P256,
                "P-384" => EcCurve::P384,
                "P-521" => EcCurve::P521,
                _ => return Err(usable("Invalid JWK EC key".into())),
            };
            let n = curve.coord_len();
            let (xb, yb) = match (pad_to(&b64_lenient(x), n), pad_to(&b64_lenient(y), n)) {
                (Some(a), Some(b)) => (a, b),
                _ => return Err(usable("Invalid JWK EC key".into())),
            };
            let mut point = vec![0x04];
            point.extend_from_slice(&xb);
            point.extend_from_slice(&yb);
            if curve != EcCurve::P521 && !ec_point_valid(curve, &point) {
                return Err(usable("error:1C800064:Provider routines::bad point: Invalid JWK EC key".into()));
            }
            return Ok(PubKey::Ec { curve, point });
        }
    }
    if let Some(first) = jwk.get("x5c").and_then(x5c_of).and_then(|a| a.into_iter().next()).flatten() {
        let cert = Cert::from_der(&b64_lenient(&first)).map_err(usable)?;
        return cert.public_key().map_err(usable);
    }
    Err("JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate".into())
}

#[derive(Clone, Debug, Default)]
pub struct GcpAnchors {
    pub trusted_jwks: Vec<Value>,
    pub trusted_key_spki: Vec<String>,
    pub root_certs_pem: Vec<String>,
}

fn root_key_of(pem: &str) -> Option<PubKey> {
    if let Ok(c) = cert_from_pem_text(pem) {
        return c.public_key().ok();
    }
    pem_public_key(pem).ok()
}

/// `verifyJwkX5cChain`: `None` when the chain anchors, else the reason.
fn verify_jwk_x5c_chain(x5c: &X5c, anchors: &GcpAnchors, now_ms: f64, skew_ms: f64) -> Option<String> {
    if x5c.is_empty() {
        return Some("empty x5c certificate chain".into());
    }
    let mut certs: Vec<Cert> = Vec::new();
    for (i, e) in x5c.iter().enumerate() {
        let b64 = match e {
            Some(s) if !s.is_empty() => s,
            _ => return Some(format!("empty x5c entry at index {i}")),
        };
        let cert = match Cert::from_der(&b64_lenient(b64)) {
            Ok(c) => c,
            Err(m) => return Some(format!("malformed x5c certificate at index {i}: {m}")),
        };
        if !x509_valid_at(&cert.raw, now_ms, skew_ms) {
            return Some(format!("x5c certificate at index {i} is outside its validity window"));
        }
        certs.push(cert);
    }
    let mut keys: Vec<PubKey> = Vec::new();
    for c in &certs {
        match c.public_key() {
            Ok(k) => keys.push(k),
            Err(m) => return Some(m),
        }
    }
    for i in 0..certs.len() - 1 {
        if !certs[i].verify(&keys[i + 1]) {
            return Some(format!("x5c link {i} is not signed by the certificate above it"));
        }
    }
    let pins: Vec<String> = lower_list(&anchors.trusted_key_spki);
    if keys.iter().any(|k| pins.contains(&k.spki_sha256_hex())) {
        return None;
    }
    let top = &certs[certs.len() - 1];
    for pem in &anchors.root_certs_pem {
        if let Some(rk) = root_key_of(pem) {
            if top.verify(&rk) {
                return None;
            }
        }
    }
    Some("x5c chain does not anchor in a configured GCP trust root".into())
}

fn pick_from<'a>(keys: &'a [Value], kid: &Option<String>) -> Option<&'a Map<String, Value>> {
    match kid {
        Some(k) if !k.is_empty() => keys.iter().filter_map(Value::as_object).find(|m| m.get("kid").and_then(Value::as_str) == Some(k.as_str())),
        _ => {
            if keys.len() == 1 {
                keys[0].as_object()
            } else {
                None
            }
        }
    }
}

/// `resolveTrustedSigningKey`: the key the token was signed under, confirmed against a configured anchor.
fn resolve_trusted_signing_key(parsed: &Jws, evidence_jwks: Option<&Value>, anchors: &GcpAnchors, now_ms: f64, skew_ms: f64) -> Result<PubKey, String> {
    let ev_keys: Vec<Value> = evidence_jwks.and_then(|j| j.get("keys")).and_then(Value::as_array).cloned().unwrap_or_default();
    let trusted = &anchors.trusted_jwks;
    let kid_set = matches!(&parsed.kid, Some(k) if !k.is_empty());
    let x5c_set = matches!(&parsed.x5c, Some(x) if !x.is_empty());
    let mut from_trusted = false;
    let mut jwk: Option<Map<String, Value>> = pick_from(&ev_keys, &parsed.kid).cloned();
    if jwk.is_none() {
        jwk = pick_from(trusted, &parsed.kid).cloned();
        from_trusted = jwk.is_some();
    }
    if jwk.is_none() && x5c_set {
        let mut m = Map::new();
        m.insert("x5c".into(), Value::Array(parsed.x5c.clone().unwrap_or_default().into_iter().map(Value::String).collect()));
        if let Some(k) = &parsed.kid {
            if !k.is_empty() {
                m.insert("kid".into(), Value::String(k.clone()));
            }
        }
        jwk = Some(m);
    }
    let jwk = match jwk {
        Some(j) => j,
        None => {
            return Err(if kid_set {
                format!("no JWKS key matches the token kid '{}' (untrusted signer)", parsed.kid.clone().unwrap_or_default())
            } else {
                "no kid on the token and no unambiguous single signing key available".to_string()
            })
        }
    };
    let key = key_from_jwk(&jwk)?;
    if from_trusted {
        return Ok(key);
    }
    let spki = key.spki_sha256_hex();
    let pins: Vec<String> = lower_list(&anchors.trusted_key_spki);
    if pins.contains(&spki) {
        return Ok(key);
    }
    for tk in trusted.iter().filter_map(Value::as_object) {
        if let Ok(tb) = key_from_jwk(tk) {
            if tb.spki_sha256_hex() == spki {
                return Ok(key);
            }
        }
    }
    let jwk_x5c = jwk.get("x5c").and_then(x5c_of).filter(|x| !x.is_empty());
    if let Some(x) = jwk_x5c {
        if !anchors.root_certs_pem.is_empty() || !pins.is_empty() {
            return match verify_jwk_x5c_chain(&x, anchors, now_ms, skew_ms) {
                None => Ok(key),
                Some(e) => Err(format!("signing key not trusted: {e}")),
            };
        }
    }
    Err("signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)".into())
}

fn verify_jws_signature(parsed: &Jws, key: &PubKey) -> Result<(), String> {
    if parsed.alg == "RS256" {
        return match key {
            PubKey::Rsa { n, e } => {
                if rsa_pkcs1_verify(n, e, Hash::Sha256, &parsed.signing_input, &parsed.signature) {
                    Ok(())
                } else {
                    Err("JWS RS256 signature does not verify under the Confidential Space signing key".into())
                }
            }
            other => Err(format!("RS256 token but signing key is {} (not RSA)", other.jwk_kty())),
        };
    }
    if parsed.alg == "ES256" {
        let is_p256 = matches!(key, PubKey::Ec { curve, .. } if *curve == EcCurve::P256);
        if !is_p256 {
            return Err(format!("ES256 token but signing key is {}/{} (not EC P-256)", key.jwk_kty(), key.jwk_crv()));
        }
        if parsed.signature.len() != 64 {
            return Err(format!("ES256 signature is {} bytes (expected 64: r\u{2016}s)", parsed.signature.len()));
        }
        if verify_p1363_sig(key, Hash::Sha256, &parsed.signing_input, &parsed.signature) {
            return Ok(());
        }
        return Err("JWS ES256 signature does not verify under the Confidential Space signing key".into());
    }
    Err(format!("unsupported JWS alg '{}' (Confidential Space uses RS256)", parsed.alg))
}

fn tee_type_of_hwmodel(m: &str) -> Option<&'static str> {
    match m {
        "GCP_AMD_SEV" | "GCP_AMD_SEV_SNP" | "GCP_AMD_SEV_ES" => return Some("sev-snp"),
        "GCP_INTEL_TDX" => return Some("tdx"),
        _ => {}
    }
    let up = m.to_uppercase();
    if up.starts_with("GCP_AMD_SEV") {
        Some("sev-snp")
    } else if up.starts_with("GCP_INTEL_TDX") {
        Some("tdx")
    } else {
        None
    }
}

/// `eat_nonce`: a single string or an array of strings, empty ones dropped.
fn nonce_candidates(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![s.clone()]
            }
        }
        Some(a) => str_array(a).map(|v| v.into_iter().filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        None => Vec::new(),
    }
}

pub struct GcpVerifier {
    trusted_issuers: Vec<String>,
    anchors: GcpAnchors,
    image_digests: Vec<String>,
    allowed_tee_types: Option<Vec<String>>,
    expected_sw_name: String,
    allowed_sw_versions: Option<Vec<String>>,
    allow_debug: bool,
    nonce_hash: Option<String>,
    skew: f64,
}

impl GcpVerifier {
    pub fn from_config(cfg: &Map<String, Value>) -> Result<GcpVerifier, String> {
        let pre = "createGcpConfidentialSpaceVerifier";
        let issuers = match cfg.get("trustedIssuers").and_then(Value::as_array) {
            Some(a) if !a.is_empty() => a,
            _ => return Err(format!("{pre}: trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs")),
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
        let jwks_keys: Vec<Value> = ta.get("trustedJwks").and_then(|j| j.get("keys")).and_then(Value::as_array).cloned().unwrap_or_default();
        let anchors = GcpAnchors {
            trusted_jwks: jwks_keys,
            trusted_key_spki: ta.get("trustedKeySpki").and_then(str_array).unwrap_or_default(),
            root_certs_pem: ta.get("rootCertsPem").and_then(str_array).unwrap_or_default(),
        };
        let count = anchors.trusted_jwks.len() + ta.get("trustedKeySpki").and_then(Value::as_array).map_or(0, |a| a.len()) + ta.get("rootCertsPem").and_then(Value::as_array).map_or(0, |a| a.len());
        if count == 0 {
            return Err(format!("{pre}: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) \u{2014} accept-all is not permitted"));
        }
        let pol = cfg.get("policy").and_then(Value::as_object);
        let digests = pol.and_then(|p| p.get("imageDigests")).and_then(Value::as_array);
        let digests = match digests {
            Some(d) if !d.is_empty() => d,
            _ => return Err(format!("{pre}: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")),
        };
        let pol = pol.unwrap_or(&empty);
        let allowed_tee = pol.get("allowedTeeTypes").and_then(Value::as_array);
        if let Some(a) = allowed_tee {
            if a.is_empty() {
                return Err(format!("{pre}: policy.allowedTeeTypes, when present, must be non-empty"));
            }
        }
        Ok(GcpVerifier {
            trusted_issuers,
            anchors,
            image_digests: digests.iter().filter_map(Value::as_str).map(|s| s.to_lowercase()).collect(),
            allowed_tee_types: allowed_tee.map(|a| a.iter().filter_map(Value::as_str).map(|s| s.to_string()).collect()),
            expected_sw_name: pol.get("expectedSwName").and_then(Value::as_str).unwrap_or("CONFIDENTIAL_SPACE").to_string(),
            allowed_sw_versions: pol.get("allowedSwVersions").and_then(str_array),
            allow_debug: pol.get("allowDebug").and_then(Value::as_bool) == Some(true),
            nonce_hash: pol.get("nonceHash").and_then(Value::as_str).map(|s| s.to_string()),
            skew: cfg.get("clockSkewMs").and_then(Value::as_f64).map_or(0.0, |s| s.max(0.0)),
        })
    }

    pub fn verify(&self, ev: Option<&Value>, now_ms: i64, expected: Option<&Binding>) -> AttResult {
        let token = match ev.and_then(|e| e.get("token")).and_then(Value::as_str) {
            Some(t) if !t.is_empty() => t,
            _ => return AttResult::fail("no GCP Confidential Space token for this action"),
        };
        let jwks = ev.and_then(|e| e.get("jwks"));
        let parsed = match parse_jws(token, "parseGcpCsJwt") {
            Ok(p) => p,
            Err(e) => return AttResult::fail(format!("Confidential Space token parse failed: {e}")),
        };
        if parsed.alg != "RS256" && parsed.alg != "ES256" {
            return AttResult::fail(format!("unsupported JWS alg '{}' (Confidential Space uses RS256)", parsed.alg));
        }
        let now = now_ms as f64;
        let key = match resolve_trusted_signing_key(&parsed, jwks, &self.anchors, now, self.skew) {
            Ok(k) => k,
            Err(r) => return AttResult::fail(format!("Confidential Space signing key invalid: {r}")),
        };
        if let Err(e) = verify_jws_signature(&parsed, &key) {
            return AttResult::fail(e);
        }
        let p = &parsed.payload;
        let iss = p.get("iss").and_then(Value::as_str);
        match iss {
            Some(i) if !i.is_empty() && self.trusted_issuers.iter().any(|t| t == i) => {}
            _ => return AttResult::fail(format!("token iss '{}' is not a configured trusted Google attestation issuer", js_str(iss))),
        }
        let now_sec = (now / 1000.0).floor();
        let skew_sec = (self.skew / 1000.0).ceil();
        let exp = match num_claim(p, "exp") {
            Some(e) => e,
            None => return AttResult::fail("token has no exp (cannot bound validity \u{2014} fail closed)"),
        };
        if now_sec - skew_sec > exp {
            return AttResult::fail("Confidential Space token expired");
        }
        if let Some(n) = num_claim(p, "nbf") {
            if now_sec + skew_sec < n {
                return AttResult::fail("Confidential Space token not yet valid (nbf)");
            }
        }
        if let Some(i) = num_claim(p, "iat") {
            if now_sec + skew_sec < i {
                return AttResult::fail("Confidential Space token issued in the future (iat)");
            }
        }
        let submods = p.get("submods").and_then(Value::as_object);
        if submods.and_then(|s| s.get("confidential_space")).and_then(Value::as_object).is_none() {
            return AttResult::fail("token carries no submods.confidential_space (not a Confidential Space token)");
        }
        let swname = p.get("swname").and_then(Value::as_str);
        if swname != Some(self.expected_sw_name.as_str()) {
            return AttResult::fail(format!("unexpected swname '{}' (expected '{}')", js_str(swname), self.expected_sw_name));
        }
        if let Some(allowed) = &self.allowed_sw_versions {
            let versions: Vec<String> = match p.get("swversion") {
                Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
                Some(v) => str_array(v).unwrap_or_default(),
                None => Vec::new(),
            };
            if !versions.iter().any(|v| allowed.contains(v)) {
                return AttResult::fail("swversion not in policy allowlist");
            }
        }
        let hwmodel = match p.get("hwmodel").and_then(Value::as_str) {
            Some(h) if !h.is_empty() => h,
            _ => return AttResult::fail("token carries no hwmodel claim"),
        };
        let tee_type = match tee_type_of_hwmodel(hwmodel) {
            Some(t) => t,
            None => return AttResult::fail(format!("unrecognized hwmodel '{hwmodel}' (not a known AMD SEV-SNP / Intel TDX model)")),
        };
        if let Some(allowed) = &self.allowed_tee_types {
            if !allowed.iter().any(|a| a == tee_type) {
                return AttResult::fail(format!("attestation type '{tee_type}' (hwmodel '{hwmodel}') is not in the policy allowlist"));
            }
        }
        let dbgstat = p.get("dbgstat").and_then(Value::as_str);
        if !self.allow_debug && dbgstat != Some("disabled-since-boot") {
            return AttResult::fail(format!("token dbgstat '{}' is not 'disabled-since-boot' (debug build \u{2014} no confidentiality)", js_str(dbgstat)));
        }
        let expected = match expected {
            Some(e) => e,
            None => return AttResult::fail("no expected attestation binding supplied"),
        };
        let binding = match attestation_binding(expected) {
            Ok(b) => transform_binding(&b, self.nonce_hash.as_deref()),
            Err(e) => return AttResult::fail(format!("binding not constructible: {e}")),
        };
        let cands = nonce_candidates(p.get("eat_nonce"));
        if cands.is_empty() {
            return AttResult::fail("token carries no eat_nonce claim to bind the PCA challenge");
        }
        let bound = cands.iter().any(|c| matches!(decode_claim_bytes(c), Some(b) if timing_safe_eq(&b, &binding)));
        if !bound {
            return AttResult::fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)");
        }
        let empty = Map::new();
        let container = submods.and_then(|s| s.get("container")).and_then(Value::as_object).unwrap_or(&empty);
        let image_digest = match container.get("image_digest").and_then(Value::as_str) {
            Some(d) if !d.is_empty() => d,
            _ => return AttResult::fail("token carries no submods.container.image_digest to measure the workload"),
        };
        if !self.image_digests.contains(&image_digest.to_lowercase()) {
            return AttResult::fail("workload image_digest not in policy allowlist");
        }
        let mut host: Vec<(&str, String)> = vec![("attestation_type", tee_type.to_string()), ("hwmodel", hwmodel.to_string()), ("image_digest", image_digest.to_string())];
        if let Some(r) = container.get("image_reference").and_then(Value::as_str) {
            if !r.is_empty() {
                host.push(("image_reference", r.to_string()));
            }
        }
        AttResult::pass(default_measured(image_digest, ""), host)
    }
}
