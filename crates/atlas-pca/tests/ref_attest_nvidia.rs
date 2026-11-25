//! Differential replay of test-data/ref-attest-nvidia.json.gz and test-data/ref-attest-nvidia-rim.json.gz (written by the TypeScript
//! reference): the NVIDIA GPU-CC attestation modules over the real public captures (H100, two GB100 GPUs, their RIMs, CRLs and OCSP
//! pairs) with byte-level mutations and synthetic PKI forged from fixed seeds: SPDM transcript parse, device chain, report signature,
//! the PCA challenge, RIM ids and comparison, CRL revocation, OCSP request / response / chain policy, the reference-manifest signature
//! verification, the collateral hook and the guarded fetch helpers over a scripted transport. Every function of each corpus has a handler
//! and the per-function totals are asserted. A reference refusal must be a refusal here; a reason that is library text (an OpenSSL
//! message, an `OCSP response rejected:` message from the ASN.1 library) is compared up to that text. The corpora store long strings
//! once in a top-level `blobs` table (`{"$blob": id}`).
mod common;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use atlas_pca::attest::nvidia_surface::*;
use atlas_pca::serde_json::{json, Map, Value};
use common::replay::{replay_cases, thrown};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

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

fn load(corpus: &str) -> Vec<Value> {
    let path = format!("{}/test-data/ref-{corpus}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "{path}: gzip failed");
    let doc: Value = serde_json::from_str(&common::sanitize_lone_surrogates(&String::from_utf8(o.stdout).expect("utf8"))).expect("parse");
    let blobs = doc["blobs"].as_object().expect("blobs").clone();
    let cases: Vec<Value> = doc["cases"].as_array().expect("cases").iter().map(|c| hydrate(c, &blobs)).collect();
    assert_eq!(cases.len() as u64, doc["count"].as_u64().unwrap(), "case count");
    cases
}

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(text(&v["$bytes"]))
}

fn enc(b: &[u8]) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect()
}

fn blob_list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().into_iter().flatten().map(bytes).collect()
}

/// A scripted one-answer transport: the response a corpus case describes, with every request logged.
fn scripted(r: &Value, log: Arc<Mutex<Vec<Value>>>) -> Arc<NvFetch> {
    let r = r.clone();
    Arc::new(move |url: &str, req: &NvRequest| {
        let mut entry = json!({"url": url, "method": req.method, "contentType": req.content_type});
        if let Some(b) = &req.body {
            entry["bodyBytes"] = json!(b.len());
        }
        log.lock().unwrap().push(entry);
        if let Some(e) = r.get("$throws") {
            return Err(text(e).to_string());
        }
        let body = match (r.get("bodyBytes"), r.get("body")) {
            (Some(b), _) => bytes(b),
            (None, Some(b)) => serde_json::to_string(b).unwrap().into_bytes(),
            (None, None) => Vec::new(),
        };
        Ok(NvResponse { status: r.get("status").and_then(Value::as_u64).unwrap_or(200) as u16, body })
    })
}

fn fetch_case(f: &str, c: &Value) -> Value {
    let log = Arc::new(Mutex::new(Vec::new()));
    let fetch = scripted(&c["response"], log.clone());
    let mut out = match f {
        "fetchRim" => match fetch_nvidia_rim(text(&c["id"]), Some(&*fetch), c.get("baseUrl").and_then(Value::as_str)) {
            Ok(v) => json!({"ok": true, "value": v}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        "fetchCrl" => match fetch_nvidia_crl(text(&c["url"]), Some(&*fetch)) {
            Ok(v) => json!({"ok": true, "value": enc(&v)}),
            Err(e) => json!({"ok": false, "error": e}),
        },
        _ => {
            let o = c.get("opts").cloned().unwrap_or(Value::Null);
            let nonce = o.get("nonce").map(bytes);
            match fetch_nvidia_ocsp(
                text(&c["certPem"]),
                text(&c["issuerPem"]),
                Some(&*fetch),
                o.get("url").and_then(Value::as_str),
                nonce.as_deref(),
            ) {
                Ok((req, res)) => json!({"ok": true, "request": enc(&req), "response": enc(&res)}),
                Err(e) => json!({"ok": false, "error": e}),
            }
        }
    };
    out["requests"] = Value::Array(log.lock().unwrap().clone());
    out
}

fn run(f: &str, a: &[Value]) -> Value {
    let now = |v: &Value| v.as_f64().unwrap_or(f64::NAN);
    match f {
        "constants" => constants(),
        "parseReport" => parse_report(&bytes(&a[0])).unwrap_or_else(thrown),
        "formatVbiosVersion" => json!(atlas_pca::attest::nvidia::format_vbios_version(&bytes(&a[0]))),
        "spkiSha256Hex" => spki_sha256_hex(text(&a[0])).map(Value::String).unwrap_or_else(thrown),
        "parsePemChain" => parse_pem_chain_summary(text(&a[0])).unwrap_or_else(thrown),
        "verifyDeviceChain" => verify_device_chain_json(text(&a[0]), &strings(&a[1]), now(&a[2])).unwrap_or_else(thrown),
        "verifySpdmSignature" => verify_spdm_signature(&bytes(&a[0]), text(&a[1])).map(Value::Bool).unwrap_or_else(thrown),
        "spdmChallenge" => spdm_challenge(&a[0]).map(|c| enc(&c)).unwrap_or_else(thrown),
        "rimIds" => rim_ids_json(&bytes(&a[0])).unwrap_or_else(thrown),
        "compareReport" => compare_report_json(&bytes(&a[0]), &a[1], &a[2]).unwrap_or_else(thrown),
        "checkRevocation" => {
            check_revocation_json(text(&a[0]), &blob_list(&a[1]), now(&a[2]), &strings(&a[3]), &a[4]).unwrap_or_else(thrown)
        }
        "fetchRim" | "fetchCrl" | "fetchOcsp" => fetch_case(f, &a[0]),
        "ocspRequest" => {
            let nonce = a[2].get("nonce").map(bytes);
            ocsp_request(text(&a[0]), text(&a[1]), nonce.as_deref(), a[2].get("hash").and_then(Value::as_str))
                .map(|r| enc(&r))
                .unwrap_or_else(thrown)
        }
        "ocspUrls" => ocsp_urls(text(&a[0])).map(|u| json!(u)).unwrap_or_else(thrown),
        "ocspVerify" => ocsp_verify_json(&bytes(&a[0]), &a[1]).unwrap_or_else(thrown),
        "ocspChain" => ocsp_chain_json(text(&a[0]), &blob_list(&a[1]), now(&a[2]), &a[3]).unwrap_or_else(thrown),
        "asn1TimesWellFormed" => json!(asn1_times_well_formed_json(&bytes(&a[0]))),
        "verifyRim" => verify_rim_json(&a[0], &strings(&a[1]["rimRootSpkiSha256"]), now(&a[1]["nowMs"])),
        "collateralHook" => {
            let c = &a[0];
            collateral_hook_json(&c["opts"], &c["bundle"], &bytes(&c["evidence"]), text(&c["chainPem"]), now(&c["nowMs"]))
                .unwrap_or_else(thrown)
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

/// A reason's library text (an OpenSSL message, the ASN.1 library's `OCSP response rejected:` text) is not compared: the reason is cut at it.
fn cut(reason: &str) -> String {
    let at = ["OCSP response rejected:", "error:"].iter().filter_map(|m| reason.find(m)).min();
    match at {
        Some(i) => reason[..i].to_string() + "<library>",
        None => reason.to_string(),
    }
}

fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.contains_key("$throws") => json!({"$throws": true}),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| match (k.as_str(), x.as_str()) {
                    ("reason" | "error" | "value", Some(r)) => (k.clone(), json!(cut(r))),
                    _ => (k.clone(), norm(x)),
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        other => other.clone(),
    }
}

fn run_norm(f: &str, a: &[Value]) -> Value {
    norm(&run(f, a))
}

fn replay_corpus(corpus: &str, total: usize, want: &[(&str, usize)]) {
    let mut cases = load(corpus);
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"]).to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = want.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(per_fn, want, "{corpus}: per-function case totals");
    for c in cases.iter_mut() {
        let w = norm(&c["out"]);
        c["out"] = w;
    }
    replay_cases(corpus, cases, total, 0, run_norm);
}

#[test]
fn nvidia_replay() {
    replay_corpus(
        "attest-nvidia",
        467,
        &[
            ("ocspVerify", 81),
            ("parseReport", 66),
            ("verifyDeviceChain", 63),
            ("checkRevocation", 39),
            ("asn1TimesWellFormed", 37),
            ("ocspChain", 30),
            ("rimIds", 26),
            ("compareReport", 26),
            ("ocspRequest", 20),
            ("verifySpdmSignature", 15),
            ("parsePemChain", 12),
            ("fetchRim", 12),
            ("spdmChallenge", 10),
            ("formatVbiosVersion", 9),
            ("ocspUrls", 8),
            ("fetchOcsp", 5),
            ("fetchCrl", 4),
            ("spkiSha256Hex", 3),
            ("constants", 1),
        ],
    );
}

#[test]
fn nvidia_rim_replay() {
    replay_corpus("attest-nvidia-rim", 163, &[("verifyRim", 108), ("collateralHook", 55)]);
}
