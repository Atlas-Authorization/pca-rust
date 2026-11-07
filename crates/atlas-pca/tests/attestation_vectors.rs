mod common;
use atlas_pca::attest::{run_attestation_vector, run_x509_vector, Binding};
use common::load;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Replays packages/pca/conformance/attestation-evidence-vectors.json: for every row, build the vendor verifier from
/// `(vendor, config)`, hand it `evidence` with the row's clock and expected binding and answer exactly `expect`. A reason
/// compares byte for byte, except rows marked `reason_match: "prefix"` (the reason embeds an OpenSSL / node:crypto exception
/// message): those compare the stable prefix. The test FAILS (never skips) when the vector file is missing.

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

fn binding_of(b: &Value) -> Binding {
    Binding {
        holder_pub: b["holderPub"].as_str().expect("holderPub").to_string(),
        grant_ref: b["grantRef"].as_str().expect("grantRef").to_string(),
        epoch: b["epoch"].as_f64().expect("epoch"),
        nonce: b["nonce"].as_str().expect("nonce").to_string(),
    }
}

fn answers(got: &Value, expect: &Value) -> bool {
    let mut want = expect.clone();
    if let Some(o) = want.as_object_mut() {
        let mode = o.remove("reason_match");
        let prefix = o.remove("reason_prefix");
        if mode.as_ref().and_then(Value::as_str) == Some("prefix") {
            let p = prefix.as_ref().and_then(Value::as_str).expect("reason_prefix");
            let mut g = got.clone();
            let reason = g.get("reason").and_then(Value::as_str).map(|s| s.to_string());
            return match reason {
                Some(r) if r.starts_with(p) => {
                    o.remove("reason");
                    if let Some(go) = g.as_object_mut() {
                        go.remove("reason");
                    }
                    g == want
                }
                _ => false,
            };
        }
    }
    *got == want
}

fn doc() -> Value {
    load("attestation-evidence-vectors.json")
}

#[test]
fn attestation_evidence_vectors() {
    let d = doc();
    let blobs = d["blobs"].as_object().expect("blobs").clone();
    let rows = d["attestation_vectors"].as_array().expect("attestation_vectors");
    assert!(rows.len() >= 900, "only {} attestation vectors", rows.len());
    let mut bad: Vec<String> = Vec::new();
    let mut by_vendor: BTreeMap<String, usize> = BTreeMap::new();
    for r in rows {
        let id = r["id"].as_str().expect("id");
        let vendor = r["vendor"].as_str().expect("vendor");
        *by_vendor.entry(vendor.to_string()).or_default() += 1;
        let config = hydrate(&r["config"], &blobs);
        let evidence = if r["evidence"].is_null() { None } else { Some(hydrate(&r["evidence"], &blobs)) };
        let binding = binding_of(&r["expected_binding"]);
        let now = r["now"].as_f64().expect("now") as i64;
        let got = run_attestation_vector(vendor, &config, evidence.as_ref(), now, Some(&binding));
        if !answers(&got, &r["expect"]) {
            let g = got.to_string();
            let e = r["expect"].to_string();
            bad.push(format!("{id}: got {} want {}", &g[..g.len().min(400)], &e[..e.len().min(400)]));
        }
    }
    for v in ["amd-sev-snp", "intel-tdx-dcap", "azure-maa", "gcp-confidential-space", "nvidia-gpu-spdm"] {
        assert!(by_vendor.get(v).copied().unwrap_or(0) > 0, "no vectors for {v}");
    }
    assert!(bad.is_empty(), "{} of {} rows differ:\n{}", bad.len(), rows.len(), bad.join("\n"));
}

#[test]
fn x509_unit_vectors() {
    let d = doc();
    let rows = d["x509_vectors"].as_array().expect("x509_vectors");
    assert!(rows.len() >= 90, "only {} x509 vectors", rows.len());
    let mut bad: Vec<String> = Vec::new();
    for r in rows {
        let id = r["id"].as_str().expect("id");
        let got = run_x509_vector(r["fn"].as_str().expect("fn"), &r["input"]);
        if got != r["expect"] {
            bad.push(format!("{id}: got {got} want {}", r["expect"]));
        }
    }
    assert!(bad.is_empty(), "{} of {} rows differ:\n{}", bad.len(), rows.len(), bad.join("\n"));
}

#[test]
fn every_accept_row_is_accepted_and_every_reject_row_is_denied() {
    let d = doc();
    let blobs = d["blobs"].as_object().expect("blobs").clone();
    let rows = d["attestation_vectors"].as_array().expect("attestation_vectors");
    let mut bad: Vec<String> = Vec::new();
    for r in rows {
        let intent = r["intent"].as_str().expect("intent");
        let config = hydrate(&r["config"], &blobs);
        let evidence = if r["evidence"].is_null() { None } else { Some(hydrate(&r["evidence"], &blobs)) };
        let binding = binding_of(&r["expected_binding"]);
        let got = run_attestation_vector(r["vendor"].as_str().unwrap(), &config, evidence.as_ref(), r["now"].as_f64().unwrap() as i64, Some(&binding));
        let accepted = got.get("ok").and_then(Value::as_bool) == Some(true);
        if accepted != (intent == "accept") {
            bad.push(format!("{}: intent {intent}, answered {got}", r["id"].as_str().unwrap()));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}
