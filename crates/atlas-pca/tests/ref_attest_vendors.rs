//! Differential replay of test-data/ref-attest-vendors.json.gz (written by the TypeScript reference): the exported functions of the
//! Intel TDX / DCAP / PCS-collateral, Azure Attestation, Google Confidential Space and AMD SEV-SNP vendor modules (quote, report and
//! JWT parsers, PCK chain, genuine-quote verifier, CRL, signed-JSON and collateral verification with the TCB / TDX-module / QE
//! statuses, x5c chain checks, JWKS fetchers over an injected transport, constants). Every case of every function is replayed and the
//! per-function totals are asserted. A reference refusal must be a refusal here; a text that comes from a library (an OpenSSL `error:`
//! message, a `JSON.parse` message, the P-256 library's point errors, `URI malformed`) is compared up to that library text, every
//! other reason exactly. Cases whose certificate bytes are not DER at all only require a refusal (counted). The corpus stores long
//! strings once in a top-level `blobs` table (`{"$blob": id}`).
mod common;
use std::cell::RefCell;
use std::collections::BTreeMap;

use atlas_pca::attest::dcap::{self, Collateral, CollateralPolicy, DcapPolicy};
use atlas_pca::attest::gcp::{self, GcpAnchors};
use atlas_pca::attest::jws::decode_canonical_b64url;
use atlas_pca::attest::maa::{self, MaaAnchors};
use atlas_pca::attest::surface::*;
use atlas_pca::attest::x509::{parse_spki, PubKey};
use atlas_pca::attest::Binding;
use atlas_pca::serde_json::{json, Map, Value};
use base64::Engine;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn hydrate(x: &Value, blobs: &Map<String, Value>) -> Value {
    match x {
        Value::Array(a) => Value::Array(a.iter().map(|e| hydrate(e, blobs)).collect()),
        Value::Object(o) => {
            if o.len() == 1 {
                if let Some(id) = o.get("$blob").and_then(Value::as_str) {
                    return blobs.get(id).cloned().unwrap_or_else(|| panic!("unknown blob {id}"));
                }
            }
            Value::Object(o.iter().map(|(k, v)| (k.clone(), hydrate(v, blobs))).collect())
        }
        other => other.clone(),
    }
}

fn load() -> Vec<Value> {
    let path = format!("{}/test-data/ref-attest-vendors.json.gz", env!("CARGO_MANIFEST_DIR"));
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "{path}: gzip failed");
    let doc: Value = serde_json::from_str(&common::sanitize_lone_surrogates(&String::from_utf8(o.stdout).expect("utf8"))).expect("parse");
    let blobs = doc["blobs"].as_object().expect("blobs").clone();
    let cases: Vec<Value> = doc["cases"].as_array().expect("cases").iter().map(|c| hydrate(c, &blobs)).collect();
    assert_eq!(cases.len() as u64, doc["count"].as_u64().unwrap(), "case count");
    cases
}

// ---- value plumbing ----

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// `{"$bytes": b64u}` -> bytes (`Err` for anything else).
fn bytes_of(v: &Value) -> Result<Vec<u8>, String> {
    let s = v.get("$bytes").and_then(Value::as_str).ok_or("expected {$bytes}")?;
    B64.decode(s.trim_end_matches('=')).map_err(|e| e.to_string())
}

fn bytes(b: &[u8]) -> Value {
    json!({ "$bytes": B64.encode(b) })
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn lower(v: &[String]) -> Vec<String> {
    v.iter().map(|s| s.to_lowercase()).collect()
}

/// A collateral member that is a string or bytes.
fn text_or_bytes(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(b) => String::from_utf8_lossy(&bytes_of(b).unwrap_or_default()).into_owned(),
        None => String::new(),
    }
}

fn binding_of(v: &Value) -> Binding {
    Binding { holder_pub: text(&v["holderPub"]).into(), grant_ref: text(&v["grantRef"]).into(), epoch: v["epoch"].as_f64().unwrap_or(f64::NAN), nonce: text(&v["nonce"]).into() }
}

fn throws(e: impl std::fmt::Display) -> Value {
    json!({ "$throws": e.to_string() })
}

fn opt_str(s: Option<String>) -> Value {
    s.map_or(Value::Null, Value::String)
}

// ---- per-function entry points ----

fn td_report_json(r: &DcapTdReport) -> Value {
    json!({ "teeTcbSvn": bytes(&r.tee_tcb_svn), "mrSeam": bytes(&r.mr_seam), "mrSignerSeam": bytes(&r.mr_signer_seam), "tdAttributes": bytes(&r.td_attributes),
        "mrTd": bytes(&r.mr_td), "mrConfigId": bytes(&r.mr_config_id), "rtmr0": bytes(&r.rtmr0), "rtmr1": bytes(&r.rtmr1), "rtmr2": bytes(&r.rtmr2),
        "rtmr3": bytes(&r.rtmr3), "reportData": bytes(&r.report_data), "raw": bytes(&r.raw) })
}

fn pck_tcb_json(t: &dcap::PckTcb) -> Value {
    json!({ "fmspc": bytes(&t.fmspc), "sgxTcbComponents": bytes(&t.sgx_tcb_components), "pcesvn": t.pcesvn, "cpusvn": bytes(&t.cpusvn) })
}

fn pin_of(a: &Value) -> String {
    a.get("trustAnchorRootCaSpkiSha256").and_then(Value::as_str).unwrap_or(INTEL_SGX_ROOT_CA_SPKI_SHA256).to_lowercase()
}

fn constants() -> Value {
    json!({
        "INTEL_DCAP_SUITE": INTEL_DCAP_SUITE, "AZURE_MAA_SUITE": AZURE_MAA_SUITE, "AZURE_MAA_SUITES": AZURE_MAA_SUITES, "GCP_CS_SUITE": GCP_CS_SUITE,
        "GCP_CS_SUITES": GCP_CS_SUITES, "GCP_CS_DEFAULT_ISSUER": GCP_CS_DEFAULT_ISSUER, "INTEL_SGX_ROOT_CA_SPKI_SHA256": INTEL_SGX_ROOT_CA_SPKI_SHA256,
        "AMD_SNP_SUITE": AMD_SNP_SUITE, "AMD_ARK_SPKI_SHA384": amd_ark_spki_sha384(), "DEFAULT_ACCEPTED_STATUSES": DEFAULT_ACCEPTED_STATUSES,
    })
}

fn parse_quote(a: &[Value]) -> Result<Value, String> {
    let q = dcap::parse_dcap_quote(&bytes_of(&a[0])?)?;
    Ok(json!({ "version": 4, "attKeyType": 2, "teeType": 129, "header": bytes(&q.header), "tdReportBody": bytes(&q.td_report_body),
        "quoteSignature": bytes(&q.quote_signature), "akPubRaw": bytes(&q.ak_pub_raw), "qeReportBody": bytes(&q.qe_report_body),
        "qeReportSignature": bytes(&q.qe_report_signature), "qeAuthData": bytes(&q.qe_auth_data), "pckChainPem": q.pck_chain_pem }))
}

fn pck_chain(a: &Value) -> Value {
    let now = a["nowMs"].as_f64().unwrap_or(f64::NAN);
    match dcap::verify_intel_pck_chain(text(&a["pckChainPem"]), &pin_of(a), now) {
        Ok(c) => {
            let point = match &c.leaf_key {
                PubKey::Ec { point, .. } => point.clone(),
                _ => Vec::new(),
            };
            json!({ "ok": true, "leafKey": { "point": bytes(&point) }, "leafDer": bytes(&c.leaf_der), "depth": c.depth })
        }
        Err((reason, true)) => json!({ "ok": false, "reason": reason, "failure": "validity" }),
        Err((reason, false)) => json!({ "ok": false, "reason": reason }),
    }
}

fn genuine_quote(a: &Value) -> Result<Value, String> {
    let mut pol = DcapPolicy::default();
    if let Some(p) = a.get("policy").filter(|p| p.is_object()) {
        pol.mrtds = lower(&strings(p.get("mrtds")));
        let gate = |k: &str| p.get(k).filter(|v| v.is_array()).map(|v| lower(&strings(Some(v))));
        pol.fmspcs = gate("fmspcs");
        pol.rtmrs = gate("rtmrs");
        pol.mr_seams = gate("mrSeams");
        pol.mr_signer_seams = gate("mrSignerSeams");
        pol.allow_debug = p.get("allowDebug") == Some(&json!(true));
    }
    let expected = a.get("expected").filter(|e| e.is_object()).map(binding_of);
    let now = a["nowMs"].as_f64().unwrap_or(f64::NAN);
    match dcap::verify_genuine_tdx_quote(&bytes_of(&a["quote"])?, &pin_of(a), now, &pol, expected.as_ref()) {
        Ok((g, q)) => {
            let report = parse_dcap_td_report(&q.td_report_body)?;
            Ok(json!({ "ok": true, "report": td_report_json(&report), "fmspc": g.fmspc, "pckTcb": pck_tcb_json(&g.pck), "akPub": { "point": bytes(&g.ak_point) },
                "chainDepth": g.chain_depth,
                "measured": { "model_id": "", "weights_digest": "", "weights_measured": false, "runtime_measurement": g.mrtd_hex, "operator": "" } }))
        }
        Err(reason) => Ok(json!({ "ok": false, "reason": reason })),
    }
}

fn verify_crl(a: &[Value]) -> Result<Value, String> {
    let key = parse_spki(&bytes_of(&a[1]["spkiDer"])?)?;
    Ok(match dcap::verify_crl(&bytes_of(&a[0])?, &key, a[2].as_f64().unwrap_or(f64::NAN)) {
        Ok(mut revoked) => {
            revoked.sort();
            json!({ "ok": true, "revoked": revoked })
        }
        Err(reason) => json!({ "ok": false, "reason": reason }),
    })
}

fn signed_json(a: &[Value]) -> Result<Value, String> {
    let key = parse_spki(&bytes_of(&a[2]["spkiDer"])?)?;
    Ok(match dcap::verify_signed_json(text(&a[0]), text(&a[1]), &key) {
        Ok(body) => json!({ "body": body }),
        Err(error) => json!({ "error": error }),
    })
}

fn collateral(a: &Value) -> Value {
    let c = a.get("collateral").filter(|c| c.is_object()).cloned().unwrap_or(Value::Null);
    let coll = Collateral {
        tcb_info_json: text_or_bytes(c.get("tcbInfoJson")),
        tcb_info_issuer_chain_pem: text_or_bytes(c.get("tcbInfoIssuerChainPem")),
        qe_identity_json: text_or_bytes(c.get("qeIdentityJson")),
        qe_identity_issuer_chain_pem: text_or_bytes(c.get("qeIdentityIssuerChainPem")),
        pck_crl_der: c.get("pckCrlDer").and_then(|v| bytes_of(v).ok()).unwrap_or_default(),
        root_crl_der: c.get("rootCrlDer").and_then(|v| bytes_of(v).ok()).unwrap_or_default(),
    };
    let mut pol = CollateralPolicy::default();
    if let Some(p) = a.get("policy").filter(|p| p.is_object()) {
        pol.accept_statuses = p.get("acceptStatuses").filter(|v| v.is_array()).map(|v| strings(Some(v)));
        pol.min_tcb_evaluation_data_number = p.get("minTcbEvaluationDataNumber").and_then(Value::as_f64);
    }
    let quote = bytes_of(&a["quote"]).unwrap_or_default();
    let r = dcap::verify_intel_tdx_collateral(&quote, &coll, a["nowMs"].as_f64().unwrap_or(f64::NAN), &pol, &pin_of(a), a.get("allowDebug") == Some(&json!(true)));
    let mut out = Map::new();
    out.insert("ok".into(), json!(r.ok));
    if let Some(reason) = r.reason {
        out.insert("reason".into(), json!(reason));
    }
    if let Some(s) = r.status {
        out.insert("status".into(), json!(s));
    }
    // present whenever the evaluation completed, including when the policy then refuses the status
    if r.platform_status.is_some() {
        out.insert("advisoryIds".into(), json!(r.advisory_ids));
    }
    for (k, v) in [("platformStatus", r.platform_status), ("tdxModuleStatus", r.tdx_module_status), ("qeStatus", r.qe_status), ("fmspc", r.fmspc)] {
        if let Some(v) = v {
            out.insert(k.into(), json!(v));
        }
    }
    if let Some(n) = r.tcb_evaluation_data_number {
        out.insert("tcbEvaluationDataNumber".into(), json!(n));
    }
    Value::Object(out)
}

/// The header of a compact JWS the parser accepted: `{alg, kid?, jku?, x5c?, typ?}` (string members only).
fn jws_header(token: &str) -> Value {
    let seg = decode_canonical_b64url(token.split('.').next().unwrap_or("")).unwrap_or_default();
    let h: Value = serde_json::from_slice(&seg).unwrap_or(Value::Null);
    let mut o = Map::new();
    for k in ["alg", "kid", "jku"] {
        if let Some(s) = h.get(k).filter(|v| v.is_string()) {
            o.insert(k.into(), s.clone());
        }
    }
    if let Some(x) = h.get("x5c").filter(|v| v.as_array().is_some_and(|a| a.iter().all(Value::is_string))) {
        o.insert("x5c".into(), x.clone());
    }
    if let Some(s) = h.get("typ").filter(|v| v.is_string()) {
        o.insert("typ".into(), s.clone());
    }
    Value::Object(o)
}

fn parsed_jws(token: &str, gcp: bool) -> Result<Value, String> {
    let j = if gcp { parse_gcp_cs_jwt(token)? } else { parse_maa_jwt(token)? };
    Ok(json!({ "header": jws_header(token), "payload": j.payload, "signingInput": bytes(&j.signing_input), "signature": bytes(&j.signature) }))
}

fn x5c_chain(a: &[Value]) -> Value {
    let x5c = maa::x5c_of(&a[0]).unwrap_or_default();
    let anchors = MaaAnchors { root_certs_pem: strings(a[1].get("rootCertsPem")), root_spki_sha256: strings(a[1].get("rootSpkiSha256")) };
    let skew = a[2].get("clockSkewMs").and_then(Value::as_f64).unwrap_or(f64::NAN);
    match maa::verify_x5c_chain(&x5c, &anchors, a[2]["nowMs"].as_f64().unwrap_or(f64::NAN), skew) {
        Ok(leaf) => {
            let spki = leaf.public_key().map(|k| k.spki_sha256_hex()).unwrap_or_default();
            json!({ "ok": true, "leafSpkiSha256": spki, "leafDer": bytes(&leaf.raw) })
        }
        Err(reason) => json!({ "ok": false, "reason": reason }),
    }
}

fn jwk_x5c_chain(a: &[Value]) -> Value {
    let x5c = maa::x5c_of(&a[0]).unwrap_or_default();
    let anchors = GcpAnchors { trusted_jwks: Vec::new(), trusted_key_spki: strings(a[1].get("trustedKeySpki")), root_certs_pem: strings(a[1].get("rootCertsPem")) };
    let skew = a[2].get("skewMs").and_then(Value::as_f64).unwrap_or(0.0);
    opt_str(gcp::verify_jwk_x5c_chain(&x5c, &anchors, a[2]["nowMs"].as_f64().unwrap_or(f64::NAN), skew))
}

/// A fetch over the corpus transport script: the i-th call answers `script[min(i, last)]`; every requested URL is logged.
fn fetch_jwks(a: &Value, gcp_issuer: bool) -> Value {
    let script = a["script"].as_array().cloned().unwrap_or_default();
    let log: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let calls = RefCell::new(0usize);
    let fetch = |url: &str| -> Result<(u16, String), String> {
        log.borrow_mut().push(url.to_string());
        let mut i = calls.borrow_mut();
        let step = &script[(*i).min(script.len() - 1)];
        *i += 1;
        if let Some(e) = step.get("$throws") {
            return Err(text(e).to_string());
        }
        let status = step.get("status").and_then(Value::as_u64).unwrap_or(200) as u16;
        let body = match step.get("body") {
            Some(b) => match b.get("$text") {
                Some(t) => text(t).to_string(),
                None => serde_json::to_string(b).unwrap_or_default(),
            },
            None => String::new(),
        };
        Ok((status, body))
    };
    let issuer = text(&a["issuer"]);
    let opts = a.get("opts").cloned().unwrap_or(Value::Null);
    let r = if gcp_issuer {
        fetch_gcp_confidential_space_jwks(issuer, &fetch, opts.get("jwksUri").and_then(Value::as_str))
    } else {
        fetch_maa_jwks(issuer, &fetch, opts.get("certsPath").and_then(Value::as_str))
    };
    let mut out = match r {
        Ok(jwks) => json!({ "ok": true, "jwks": jwks }),
        Err(error) => json!({ "ok": false, "error": error }),
    };
    out["requests"] = json!(log.borrow().clone());
    out
}

fn run(c: &Value) -> Result<Value, String> {
    let args = c["args"].as_array().cloned().unwrap_or_default();
    let a = &args;
    match text(&c["fn"]) {
        "constants" => Ok(constants()),
        "toHex" => Ok(json!(to_hex(&bytes_of(&a[0])?))),
        "pemToDer" => Ok(bytes(&pem_to_der(text(&a[0]))?)),
        "ecdsaP256PublicKey" => Ok(json!({ "point": bytes(&ecdsa_p256_public_key(&bytes_of(&a[0])?)?) })),
        "parseDcapTdReport" => Ok(td_report_json(&parse_dcap_td_report(&bytes_of(&a[0])?)?)),
        "parseDcapQuote" => parse_quote(a),
        "extractPckFmspcAndTcb" => Ok(pck_tcb_json(&dcap::extract_pck_fmspc_and_tcb(&bytes_of(&a[0])?)?)),
        "verifyIntelPckChainX509" => Ok(pck_chain(&a[0])),
        "verifyGenuineTdxQuote" => genuine_quote(&a[0]),
        "verifyCrl" => verify_crl(a),
        "serialIsRevoked" => Ok(json!(dcap::serial_is_revoked(&strings(Some(&a[0])), text(&a[1])))),
        "verifySignedJson" => signed_json(a),
        "decodeIssuerChainHeader" => Ok(json!(decode_issuer_chain_header(text(&a[0]))?)),
        "verifyIntelTdxCollateral" => Ok(collateral(&a[0])),
        "checkAzureRuntimeDataBinding" => {
            Ok(opt_str(atlas_pca::attest::check_azure_runtime_data_binding(&bytes_of(&a[0])?, &bytes_of(&a[1])?, &binding_of(&a[2]))))
        }
        "parseMaaJwt" => parsed_jws(text(&a[0]), false),
        "parseGcpCsJwt" => parsed_jws(text(&a[0]), true),
        "verifyX5cChain" => Ok(x5c_chain(a)),
        "verifyJwkX5cChain" => Ok(jwk_x5c_chain(a)),
        "teeTypeOfHwModel" => Ok(opt_str(gcp::tee_type_of_hwmodel(text(&a[0])).map(String::from))),
        "fetchMaaJwks" => Ok(fetch_jwks(&a[0], false)),
        "fetchGcpConfidentialSpaceJwks" => Ok(fetch_jwks(&a[0], true)),
        other => panic!("no native entry point for {other}"),
    }
}

// ---- comparison ----

/// Where a library text starts inside a reference text (OpenSSL `error:<8 hex>:`, a JSON.parse message, the P-256 point errors, `URI malformed`).
fn library_text_at(s: &str) -> Option<usize> {
    let mut at = ["Unexpected ", "bad point: ", "invalid Point, expected length", "URI malformed"].iter().filter_map(|m| s.find(m)).min();
    if let Some(i) = s.find("error:") {
        let hex = s[i + 6..].chars().take(8).collect::<String>();
        if hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            at = Some(at.map_or(i, |a| a.min(i)));
        }
    }
    at
}

fn same_text(want: &str, got: &str) -> bool {
    match library_text_at(want) {
        Some(i) => got.starts_with(&want[..i]) && got.len() >= i,
        None => want == got,
    }
}

/// Equality that compares library texts by their fixed prefix (every other string exactly).
fn same(want: &Value, got: &Value) -> bool {
    match (want, got) {
        (Value::String(w), Value::String(g)) => same_text(w, g),
        (Value::Array(w), Value::Array(g)) => w.len() == g.len() && w.iter().zip(g).all(|(x, y)| same(x, y)),
        (Value::Object(w), Value::Object(g)) => w.len() == g.len() && w.iter().all(|(k, v)| g.get(k).is_some_and(|y| same(v, y))),
        _ => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(got),
    }
}

/// A reference refusal, in any of the corpus shapes.
fn refused(v: &Value) -> bool {
    v.get("$throws").is_some() || v.get("ok") == Some(&json!(false)) || v.get("error").is_some() || (v.is_string())
}

/// Cases whose certificate bytes are not DER at all: any stack refuses them, with its own text.
fn refusal_only(name: &str) -> bool {
    ["malformed-certificate", "malformed-base64-certificate", "malformed-second-certificate", "anchor-malformed-pem", "pem-malformed-block"]
        .iter()
        .any(|m| name.contains(m))
}

#[test]
fn vendor_attestation_functions_match_the_reference() {
    let cases = load();
    assert_eq!(cases.len(), 758, "case total");
    let (mut bad, mut relaxed) = (Vec::new(), 0usize);
    let mut per: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        let f = text(&c["fn"]).to_string();
        *per.entry(f).or_default() += 1;
        let got = match run(c) {
            Ok(v) => v,
            Err(e) => throws(e),
        };
        let want = &c["out"];
        let ok = if refusal_only(text(&c["name"])) && (refused(want) || want.is_string()) {
            relaxed += 1;
            refused(&got) || got.is_string()
        } else if want.get("$throws").is_some() {
            got.get("$throws").is_some_and(|g| same_text(text(&want["$throws"]), text(g)))
        } else {
            same(want, &got)
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], want, got));
        }
    }
    let want_counts: [(&str, usize); 22] = [
        ("checkAzureRuntimeDataBinding", 24), ("constants", 1), ("decodeIssuerChainHeader", 13), ("ecdsaP256PublicKey", 12), ("extractPckFmspcAndTcb", 25),
        ("fetchGcpConfidentialSpaceJwks", 26), ("fetchMaaJwks", 22), ("parseDcapQuote", 45), ("parseDcapTdReport", 11), ("parseGcpCsJwt", 57),
        ("parseMaaJwt", 57), ("pemToDer", 10), ("serialIsRevoked", 10), ("teeTypeOfHwModel", 15), ("toHex", 8), ("verifyCrl", 34),
        ("verifyGenuineTdxQuote", 64), ("verifyIntelPckChainX509", 46), ("verifyIntelTdxCollateral", 159), ("verifyJwkX5cChain", 27),
        ("verifySignedJson", 31), ("verifyX5cChain", 61),
    ];
    for (f, n) in want_counts {
        assert_eq!(per.get(f), Some(&n), "{f}: case count");
    }
    assert_eq!(per.len(), want_counts.len(), "an unexpected function in the corpus");
    assert_eq!(relaxed, 6, "the refusal-only cases (certificate bytes that are not DER)");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(12).cloned().collect::<Vec<_>>().join("\n"));
}
