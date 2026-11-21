//! JSON-valued entry points of the NVIDIA GPU-CC attestation modules (SPDM transcript, device chain, reference manifests, revocation and
//! OCSP) in the reference's own shapes, for the per-function surface the typed verifier in [`super::nvidia`] is built from: the report
//! summary, certificate summaries, the chain verdict, the RIM ids and comparison, the CRL / OCSP checks, the request builder, the
//! collateral hook and the guarded fetch helpers over an INJECTED transport (no default transport is bundled). `Err` is the
//! reference's throw.
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::nvidia::*;
use super::ocsp::{
    asn1_times_well_formed, build_ocsp_request, cert_ocsp_urls, check_chain_ocsp_with, verify_ocsp_response_with, ChainOcspOpts, OcspOpts, RequireGood, Status,
    DEFAULT_MAX_AGE_MS, NVIDIA_OCSP_URL,
};
use super::rim::{verify_nvidia_rim, VerifiedRim};
use super::util::{hex_lower, sha256};
use super::x509::{pem_blocks, verify_p1363_sig, Cert, Hash};
use super::{attestation_binding, der, Binding};

/// The suite identifier of this root.
pub const NVIDIA_SPDM_SUITE: &str = "nvidia-gpu-spdm-ecdsa-p384-sha384";
/// The RIM service the reference manifests are fetched from.
pub const NVIDIA_RIM_BASE_URL: &str = "https://rim.attestation.nvidia.com/v1/rim/";
/// The CRLs of a Hopper device chain.
pub const NVIDIA_GH100_CRL_URLS: [&str; 2] = ["https://crl.ndis.nvidia.com/crl/l2-gh100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"];
/// The CRLs of a Blackwell device chain.
pub const NVIDIA_GB100_CRL_URLS: [&str; 2] = ["https://crl.ndis.nvidia.com/crl/l2-gb100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"];
/// The opaque-data TLV ids the module surfaces by name.
pub const NVIDIA_OPAQUE: [(&str, u16); 14] = [
    ("CERT_ISSUER_NAME", 1),
    ("CERT_AUTHORITY_KEY_IDENTIFIER", 2),
    ("DRIVER_VERSION", 3),
    ("GPU_INFO", 4),
    ("SKU", 5),
    ("VBIOS_VERSION", 6),
    ("MANUFACTURER_ID", 7),
    ("TAMPER_DETECTION", 8),
    ("MSRSCNT", 12),
    ("BOARD_ID", 14),
    ("FWID", 20),
    ("OPAQUE_DATA_VERSION", 34),
    ("CHIP_INFO", 35),
    ("FEATURE_FLAG", 36),
];

/// The exported constants of the three modules.
pub fn constants() -> Value {
    let opaque: Map<String, Value> = NVIDIA_OPAQUE.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
    json!({
        "NVIDIA_SPDM_SUITE": NVIDIA_SPDM_SUITE,
        "NVIDIA_OPAQUE": Value::Object(opaque),
        "NVIDIA_RIM_BASE_URL": NVIDIA_RIM_BASE_URL,
        "NVIDIA_GH100_CRL_URLS": NVIDIA_GH100_CRL_URLS,
        "NVIDIA_GB100_CRL_URLS": NVIDIA_GB100_CRL_URLS,
        "NVIDIA_OCSP_URL": NVIDIA_OCSP_URL,
        "NVIDIA_OCSP_DEFAULT_MAX_AGE_MS": DEFAULT_MAX_AGE_MS,
    })
}

fn bytes_json(b: &[u8]) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

/// `parseNvidiaSpdmEvidence` summarised: `{request: {version, code, param1, param2, nonce, slot}, response: {version, code, numBlocks,
/// measurements: [{index, valueType, digest}], responderNonce, opaque: {<type>: bytes}, signature}, signedBytesLength,
/// signedBytesSha256}`. `Err` on any structural problem.
pub fn parse_report(bytes: &[u8]) -> Result<Value, String> {
    let s = parse_spdm(bytes)?;
    let measurements: Vec<Value> =
        s.measurements.iter().zip(&s.value_types).map(|((i, d), t)| json!({"index": i, "valueType": t, "digest": bytes_json(d)})).collect();
    let mut types: Vec<&u16> = s.opaque.keys().collect();
    types.sort();
    let opaque: Map<String, Value> = types.into_iter().map(|t| (t.to_string(), bytes_json(&s.opaque[t]))).collect();
    Ok(json!({
        "request": {"version": s.request_version, "code": bytes[1], "param1": s.request_params.0, "param2": s.request_params.1, "nonce": bytes_json(&s.request_nonce), "slot": s.request_params.2},
        "response": {
            "version": s.response_version,
            "code": 0x60,
            "numBlocks": s.measurements.len(),
            "measurements": measurements,
            "responderNonce": bytes_json(&s.responder_nonce),
            "opaque": Value::Object(opaque),
            "signature": bytes_json(&s.signature),
        },
        "signedBytesLength": s.signed.len(),
        "signedBytesSha256": hex_lower(&sha256(&s.signed)),
    }))
}

/// Node's `validFrom` / `validTo` rendering of an instant (`Oct 17 00:00:00 2020 GMT`, the day space-padded).
fn openssl_time(ms: i64) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{} {:>2} {:02}:{:02}:{:02} {} GMT", MONTHS[(m - 1) as usize], d, rem / 3600, (rem % 3600) / 60, rem % 60, y)
}

/// A certificate as the reference summarises it: `{subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}`.
pub fn cert_summary(c: &Cert) -> Result<Value, String> {
    let (from, to) = der::der_validity_ms(&c.raw);
    Ok(json!({
        "subject": c.subject_string(),
        "issuer": c.issuer_string(),
        "serial": c.serial_hex(),
        "notBefore": from.map_or("Invalid Date".to_string(), openssl_time),
        "notAfter": to.map_or("Invalid Date".to_string(), openssl_time),
        "spkiSha256": c.public_key()?.spki_sha256_hex(),
        "rawSha256": hex_lower(&sha256(&c.raw)),
        "ca": c.is_ca(),
    }))
}

/// `spkiSha256Hex(cert)` of a PEM certificate: SHA-256 of its SubjectPublicKeyInfo, lowercase hex.
pub fn spki_sha256_hex(cert_pem: &str) -> Result<String, String> {
    Ok(super::maa::cert_from_pem_text(cert_pem)?.public_key()?.spki_sha256_hex())
}

const MAX_CHAIN: usize = 5;

/// `parsePemChain`: the certificates of a PEM bundle, leaf first. `Err` on none, too many (more than 5) or one that does not parse.
pub fn parse_pem_chain(pem: &str) -> Result<Vec<Cert>, String> {
    let blocks = pem_blocks(pem);
    if blocks.is_empty() {
        return Err("parsePemChain: no certificates found".into());
    }
    if blocks.len() > MAX_CHAIN {
        return Err(format!("parsePemChain: chain longer than {MAX_CHAIN}"));
    }
    blocks.iter().map(|b| Cert::from_pem(b)).collect()
}

/// `parsePemChain` summarised.
pub fn parse_pem_chain_summary(pem: &str) -> Result<Value, String> {
    Ok(Value::Array(parse_pem_chain(pem)?.iter().map(cert_summary).collect::<Result<Vec<_>, _>>()?))
}

/// `verifyNvidiaDeviceChain`: `{ok: true, leaf, chain}` (certificate summaries) or `{ok: false, reason}`.
pub fn verify_device_chain_json(pem: &str, root_pins: &[String], now_ms: f64) -> Result<Value, String> {
    Ok(match verify_device_chain(pem, root_pins, now_ms) {
        Ok(c) => json!({"ok": true, "leaf": cert_summary(&c.leaf)?, "chain": c.chain.iter().map(cert_summary).collect::<Result<Vec<_>, _>>()?}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    })
}

/// `verifyNvidiaSpdmSignature` of the parsed report under the leaf key of `chain_pem`. `Err` where the reference throws (a transcript
/// or a chain that does not parse, a leaf key the platform cannot read).
pub fn verify_spdm_signature(evidence: &[u8], chain_pem: &str) -> Result<bool, String> {
    let report = parse_spdm(evidence)?;
    let leaf = parse_pem_chain(chain_pem)?.into_iter().next().ok_or("no certificate")?;
    let key = leaf.public_key()?;
    Ok(verify_p1363_sig(&key, Hash::Sha384, &report.signed, &report.signature))
}

/// The 32-byte SPDM challenge that carries the PCA binding: `sha256(attestationBinding(expected))`. `Err` for an invalid binding.
pub fn spdm_challenge(expected: &Value) -> Result<Vec<u8>, String> {
    let s = |k: &str| expected.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let b = Binding { holder_pub: s("holderPub"), grant_ref: s("grantRef"), epoch: expected.get("epoch").and_then(Value::as_f64).unwrap_or(f64::NAN), nonce: s("nonce") };
    Ok(sha256(&attestation_binding(&b)?))
}

/// `nvidiaRimIdsForReport(parse(bytes))`: `{chip, driver, vbios, driverVersion, vbiosVersion}` or `null`.
pub fn rim_ids_json(bytes: &[u8]) -> Result<Value, String> {
    Ok(match rim_ids_for_report(&parse_spdm(bytes)?) {
        Some(i) => json!({"chip": i.chip, "driver": i.driver, "vbios": i.vbios, "driverVersion": i.driver_version, "vbiosVersion": i.vbios_version}),
        None => Value::Null,
    })
}

fn rim_from_summary(v: &Value) -> Result<VerifiedRim, String> {
    let mut golden = std::collections::BTreeMap::new();
    for g in v.get("golden").and_then(Value::as_array).ok_or("rim.golden is not iterable")? {
        let index = g["index"].as_i64().ok_or("golden.index")?;
        golden.insert(
            index,
            super::rim::Golden {
                index,
                active: g["active"] == json!(true),
                size: g["size"].as_u64().unwrap_or(0) as usize,
                hashes: g["hashes"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
            },
        );
    }
    Ok(VerifiedRim {
        tag_id: v["tagId"].as_str().unwrap_or("").into(),
        product: v["product"].as_str().unwrap_or("").into(),
        version: v["version"].as_str().unwrap_or("").into(),
        golden,
        signer_subject: v["signerSubject"].as_str().unwrap_or("").into(),
    })
}

/// A verified RIM summarised: `{tagId, product, version, golden: [{index, active, alternatives, size, hashes}] (ascending index),
/// signerSubject}`.
pub fn rim_summary(r: &VerifiedRim) -> Value {
    let golden: Vec<Value> = r
        .golden
        .values()
        .map(|g| json!({"index": g.index, "active": g.active, "alternatives": g.hashes.len(), "size": g.size, "hashes": g.hashes}))
        .collect();
    json!({"tagId": r.tag_id, "product": r.product, "version": r.version, "golden": golden, "signerSubject": r.signer_subject})
}

/// `verifyNvidiaRim(xml, {rimRootSpkiSha256, nowMs})`: `{ok: true, rim}` or `{ok: false, reason}`. A document that is not a string is
/// refused like an empty one.
pub fn verify_rim_json(xml: &Value, root_pins: &[String], now_ms: f64) -> Value {
    let Some(text) = xml.as_str() else { return json!({"ok": false, "reason": "RIM: empty or oversized document"}) };
    match verify_nvidia_rim(text, root_pins, now_ms) {
        Ok(r) => json!({"ok": true, "rim": rim_summary(&r)}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    }
}

/// `compareReportToRims(parse(bytes), driverRim, vbiosRim)` over RIM summaries: `{ok: true, checked}` or `{ok: false, reason,
/// mismatches?: [{index, source}]}`.
pub fn compare_report_json(bytes: &[u8], driver: &Value, vbios: &Value) -> Result<Value, String> {
    let spdm = parse_spdm(bytes)?;
    Ok(match compare_report_detail(&spdm, &rim_from_summary(driver)?, &rim_from_summary(vbios)?) {
        Ok(checked) => json!({"ok": true, "checked": checked}),
        Err((reason, mismatches)) if mismatches.is_empty() => json!({"ok": false, "reason": reason}),
        Err((reason, mismatches)) => {
            json!({"ok": false, "reason": reason, "mismatches": mismatches.iter().map(|(i, s)| json!({"index": i, "source": s})).collect::<Vec<_>>()})
        }
    })
}

/// `checkNvidiaChainRevocation(parsePemChain(chain_pem), crls, nowMs, requireIssuers, requireFor)`: `{ok: true, verifiedCrls}` or
/// `{ok: false, reason}`. `require_for` is `cdp`, `all`, `none` or a list of chain indices.
pub fn check_revocation_json(chain_pem: &str, crls: &[Vec<u8>], now_ms: f64, require_issuers: &[String], require_for: &Value) -> Result<Value, String> {
    let chain = parse_pem_chain(chain_pem)?;
    let policy = match require_for {
        Value::String(s) if s == "all" => RequireCrlFor::All,
        Value::String(s) if s == "none" => RequireCrlFor::None,
        Value::Array(list) => {
            let mut ok: Vec<i64> = Vec::new();
            let mut bad: Option<String> = None;
            for x in list {
                match x.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() < 9e15) {
                    Some(f) if bad.is_none() => ok.push(f as i64),
                    Some(_) => {}
                    None if bad.is_none() => bad = Some(crate::intent_v2::js_value_string(x)),
                    None => {}
                }
            }
            match bad {
                Some(text) => RequireCrlFor::Invalid(ok, text),
                None => RequireCrlFor::Indices(ok),
            }
        }
        _ => RequireCrlFor::Cdp,
    };
    Ok(match check_chain_revocation_for(&chain, crls, now_ms, require_issuers, &policy) {
        Ok(()) => json!({"ok": true, "verifiedCrls": crls.len()}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    })
}

/// `nvidiaCollateralHook(opts)` run on a report: the hook's verdict `{value: <reason> | null}` (`null` = accepted). `bundle` is
/// `{driverRimXml, vbiosRimXml, crls?, ocsp?}` or `null` (the resolver returned nothing); the chain is parsed from `chain_pem`. `Err` where
/// the reference throws (a malformed configuration, a transcript or chain that does not parse).
pub fn collateral_hook_json(opts: &Value, bundle: &Value, evidence: &[u8], chain_pem: &str, now_ms: f64) -> Result<Value, String> {
    let col = opts.as_object().ok_or("Cannot read properties of null (reading 'rimRootSpkiSha256')")?;
    let cfg = CollateralConfig::from_config(col)?;
    let spdm = parse_spdm(evidence)?;
    let chain = parse_pem_chain(chain_pem)?;
    let nv = NvChain { leaf: chain[0].clone(), chain };
    let list = |k: &str| -> Vec<Vec<u8>> {
        use base64::Engine;
        bundle.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(|b| b.get("$bytes").and_then(Value::as_str)).map(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap_or_default()).collect()
    };
    let b = (!bundle.is_null()).then(|| CollateralBundle {
        driver_rim: bundle["driverRimXml"].as_str().unwrap_or("").to_string(),
        vbios_rim: bundle["vbiosRimXml"].as_str().unwrap_or("").to_string(),
        crls: list("crls"),
        ocsp: list("ocsp"),
    });
    Ok(json!({"value": collateral_hook(&cfg, &spdm, &nv, b.as_ref(), now_ms)}))
}

// ---- OCSP ------------------------------------------------------------------------------------------------------------------------

/// `buildNvidiaOcspRequest(cert, issuer, {nonce?, hash?})` over PEM certificates.
pub fn ocsp_request(cert_pem: &str, issuer_pem: &str, nonce: Option<&[u8]>, hash: Option<&str>) -> Result<Vec<u8>, String> {
    let c = super::maa::cert_from_pem_text(cert_pem)?;
    let i = super::maa::cert_from_pem_text(issuer_pem)?;
    build_ocsp_request(&c, &i, nonce, hash)
}

/// `nvidiaCertOcspUrls(cert)` of a PEM certificate.
pub fn ocsp_urls(cert_pem: &str) -> Result<Vec<String>, String> {
    Ok(cert_ocsp_urls(&super::maa::cert_from_pem_text(cert_pem)?))
}

fn status_name(s: Status) -> &'static str {
    match s {
        Status::Good => "good",
        Status::Revoked => "revoked",
        Status::Unknown => "unknown",
        Status::Absent => "absent",
    }
}

/// `verifyNvidiaOcspResponse(responseDer, {cert, issuer, chain, nowMs, maxAgeMs?, expectedNonce?, clockSkewMs?})` with the chain a PEM
/// bundle and `cert` / `issuer` its members by index: `{ok: true, status, thisUpdate, nextUpdate?, producedAt, revokedAt?,
/// revocationReason?, responder}` or `{ok: false, reason}`.
pub fn ocsp_verify_json(der: &[u8], o: &Value) -> Result<Value, String> {
    let chain = parse_pem_chain(o["chainPem"].as_str().unwrap_or(""))?;
    let at = |k: &str| chain.get(o[k].as_u64().unwrap_or(u64::MAX) as usize).ok_or_else(|| format!("Cannot read properties of undefined (reading '{k}')"));
    let (cert, issuer) = (at("certIndex")?, at("issuerIndex").or_else(|_| chain.get(o["certIndex"].as_u64().unwrap_or(0) as usize + 1).ok_or_else(|| "no issuer".to_string()))?);
    let opts = OcspOpts {
        max_age_ms: o.get("maxAgeMs").and_then(Value::as_f64).unwrap_or(DEFAULT_MAX_AGE_MS),
        clock_skew_ms: o.get("clockSkewMs").and_then(Value::as_f64).unwrap_or(0.0),
        expected_nonce: o.get("expectedNonce").and_then(|n| n.get("$bytes")).and_then(Value::as_str).map(|s| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap_or_default()
        }),
    };
    let now = o["nowMs"].as_f64().unwrap_or(f64::NAN);
    Ok(match verify_ocsp_response_with(der, cert, issuer, &chain, now, &opts) {
        Err(reason) => {
            // a refusal that does not already say so is the reference's `OCSP response rejected: <message>`
            json!({"ok": false, "reason": reason})
        }
        Ok(r) => {
            let mut v = json!({"ok": true, "status": status_name(r.status), "thisUpdate": r.this_update, "producedAt": r.produced_at, "responder": if r.delegated { "delegated" } else { "issuer" }});
            if let Some(n) = r.next_update {
                v["nextUpdate"] = json!(n);
            }
            if let Some(n) = r.revoked_at {
                v["revokedAt"] = json!(n);
            }
            if let Some(n) = r.revocation_reason {
                v["revocationReason"] = json!(n);
            }
            v
        }
    })
}

/// `checkNvidiaChainOcsp(chain, responses, nowMs, opts)`: `{ok: true, verifiedCrls: 0, verifiedOcsp, statuses}` or `{ok: false, reason,
/// statuses?}`. `opts` is `{requireGood?: aia | all | [index], maxAgeMs?, clockSkewMs?, expectedNonces?: [bytes | null]}`.
pub fn ocsp_chain_json(chain_pem: &str, responses: &[Vec<u8>], now_ms: f64, o: &Value) -> Result<Value, String> {
    use base64::Engine;
    let chain = parse_pem_chain(chain_pem)?;
    let require_good = match o.get("requireGood") {
        Some(Value::String(s)) if s == "all" => RequireGood::All,
        Some(Value::Array(a)) => RequireGood::Indices(a.iter().map(|x| x.as_f64().unwrap_or(f64::NAN)).collect()),
        _ => RequireGood::Aia,
    };
    let opts = ChainOcspOpts {
        require_good,
        max_age_ms: o.get("maxAgeMs").and_then(Value::as_f64),
        clock_skew_ms: o.get("clockSkewMs").and_then(Value::as_f64),
        expected_nonces: o
            .get("expectedNonces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|n| n.get("$bytes").and_then(Value::as_str).map(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap_or_default()))
            .collect(),
    };
    let table = |st: &[Status]| -> Value { Value::Object(st.iter().enumerate().map(|(i, s)| (i.to_string(), json!(status_name(*s)))).collect()) };
    Ok(match check_chain_ocsp_with(&chain, responses, now_ms, &opts) {
        Ok(ok) => json!({"ok": true, "verifiedCrls": 0, "verifiedOcsp": ok.verified_ocsp, "statuses": table(&ok.statuses)}),
        Err(e) => {
            let mut v = json!({"ok": false, "reason": e.reason});
            if let Some(st) = &e.statuses {
                v["statuses"] = table(st);
            }
            v
        }
    })
}

/// `allAsn1TimesWellFormed` over a DER value.
pub fn asn1_times_well_formed_json(der: &[u8]) -> bool {
    asn1_times_well_formed(der)
}

// ---- guarded fetch helpers over an injected transport ----------------------------------------------------------------------------

/// What a request asks of the transport: the method, the content type of the body (if any) and the body.
#[derive(Clone, Debug, Default)]
pub struct NvRequest {
    pub method: &'static str,
    pub content_type: Option<&'static str>,
    pub body: Option<Vec<u8>>,
}

/// The transport's answer.
#[derive(Clone, Debug, Default)]
pub struct NvResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// An injected transport: a URL and a request in, the response out; `Err` is a transport failure.
pub type NvFetch = dyn Fn(&str, &NvRequest) -> Result<NvResponse, String> + Send + Sync;

fn ok_status(r: &NvResponse) -> bool {
    (200..=299).contains(&r.status)
}

/// `fetchNvidiaRim(id, {fetch, baseUrl?})`: the RIM XML text. `Err` without a transport, for an id outside `[A-Za-z0-9_.-]+`, on a
/// failed status, on a body that is not JSON with a string `rim` member (base64 of the XML).
pub fn fetch_nvidia_rim(id: &str, fetch: Option<&NvFetch>, base_url: Option<&str>) -> Result<String, String> {
    let Some(fetch) = fetch else { return Err("fetchNvidiaRim: no fetch implementation available".into()) };
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-') {
        return Err("fetchNvidiaRim: invalid RIM id".into());
    }
    let res = fetch(&format!("{}{id}", base_url.unwrap_or(NVIDIA_RIM_BASE_URL)), &NvRequest { method: "GET", ..Default::default() })?;
    if !ok_status(&res) {
        return Err(format!("RIM fetch failed: HTTP {} for {id}", res.status));
    }
    let body: Value = serde_json::from_slice(&res.body).map_err(|e| e.to_string())?;
    let rim = body.get("rim").and_then(Value::as_str).ok_or("RIM fetch: response has no rim field")?;
    let raw = super::util::b64_lenient(rim);
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// `fetchNvidiaCrl(url, {fetch})`: the CRL bytes.
pub fn fetch_nvidia_crl(url: &str, fetch: Option<&NvFetch>) -> Result<Vec<u8>, String> {
    let Some(fetch) = fetch else { return Err("fetchNvidiaCrl: no fetch implementation available".into()) };
    let res = fetch(url, &NvRequest { method: "GET", ..Default::default() })?;
    if !ok_status(&res) {
        return Err(format!("CRL fetch failed: HTTP {} for {url}", res.status));
    }
    Ok(res.body)
}

/// `fetchNvidiaOcsp(cert, issuer, {fetch, url?, nonce?})`: `(request, response)` DER bytes (the request is POSTed as
/// `application/ocsp-request` to `url`, default [`NVIDIA_OCSP_URL`]).
pub fn fetch_nvidia_ocsp(
    cert_pem: &str,
    issuer_pem: &str,
    fetch: Option<&NvFetch>,
    url: Option<&str>,
    nonce: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let Some(fetch) = fetch else { return Err("fetchNvidiaOcsp: no fetch implementation available".into()) };
    let request = ocsp_request(cert_pem, issuer_pem, nonce, None)?;
    let res = fetch(url.unwrap_or(NVIDIA_OCSP_URL), &NvRequest { method: "POST", content_type: Some("application/ocsp-request"), body: Some(request.clone()) })?;
    if !ok_status(&res) {
        return Err(format!("OCSP fetch failed: HTTP {}", res.status));
    }
    Ok((request, res.body))
}

/// A shared transport handle.
pub type SharedNvFetch = Arc<NvFetch>;
