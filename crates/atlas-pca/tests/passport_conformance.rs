mod common;
use atlas_pca::*;
use common::*;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// Replays packages/pca/conformance/passport-vectors.json (signed agent passport): every signature suite this crate
/// implements (a suite it does not implement must answer `unsupported_suite`), and the hardware branch through a stub
/// vendor verifier that answers what the vector says. The `passport_hardware_vectors` table is replayed below through the
/// crate's own vendor verifiers.
#[test]
fn passport_vectors() {
    let doc = load("passport-vectors.json");
    let vs = doc["passport_vectors"].as_array().expect("vectors");
    assert!(vs.len() >= 74, "only {} vectors", vs.len());
    let supported = supported_suites();
    let mut docs: HashMap<String, Value> = HashMap::new();
    let (mut bad, mut pq_seen) = (Vec::new(), 0);
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let signed = match v.get("signed_ref").and_then(|r| r.as_str()) {
            Some(r) => docs[r].clone(),
            None => v["signed"].clone(),
        };
        docs.insert(name.to_string(), signed.clone());
        let issuers: Vec<String> = v["trustedIssuers"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let revoked: Vec<String> = v["revoked"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let f = |id: &str, _: &str, _: &str| -> Result<bool, ()> { Ok(revoked.iter().any(|r| r == id)) };
        let pins: Option<HashMap<String, String>> = v.get("pqPins").and_then(|p| p.as_object()).map(|p| p.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap().to_string())).collect());
        let seen = std::cell::RefCell::new(None::<PassportBinding>);
        let stub = v.get("hardware").cloned();
        let attest = |_: &Value, b: &PassportBinding| -> Result<PassportAttestation, ()> {
            *seen.borrow_mut() = Some(PassportBinding { holder_pub: b.holder_pub.clone(), grant_ref: b.grant_ref.clone(), epoch: b.epoch, nonce: b.nonce.clone() });
            let h = stub.as_ref().unwrap();
            if h["throws"].as_bool() == Some(true) {
                return Err(());
            }
            Ok(PassportAttestation { ok: h["ok"].as_bool() == Some(true), bound: h["bound"].as_bool() == Some(true), measured: h["measured"].as_object().cloned().map(|m: Map<String, Value>| m) })
        };
        let o = PassportOptions {
            trusted_issuers: &issuers,
            now_ms: v["now"].as_i64().unwrap(),
            clock_skew_ms: v.get("clockSkewMs").and_then(|x| x.as_i64()),
            max_evidence_age_ms: v.get("maxEvidenceAgeMs").and_then(|x| x.as_i64()),
            subject: v.get("subject").and_then(|x| x.as_str()),
            pq_pins: pins.as_ref(),
            attest: if stub.is_some() { Some(&attest) } else { None },
            default_verifier: None,
            revoked: Some(&f),
        };
        let got = verify_passport(&signed, &o);
        let mut want = if v["expect"]["ok"].as_bool() == Some(true) { Ok(()) } else { Err(v["expect"]["reason"].as_str().unwrap()) };
        if let Some(alg) = signed.get("alg").and_then(|a| a.as_str()) {
            if !supported.contains(&alg) {
                want = Err("unsupported_suite");
            } else {
                pq_seen += 1;
            }
        }
        if got != want {
            bad.push(format!("{name}: got {got:?} want {want:?}"));
        }
        if let Some(eb) = v.get("expectBinding") {
            let s = seen.borrow();
            let ok = s.as_ref().is_some_and(|b| b.holder_pub == eb["holderPub"].as_str().unwrap() && b.grant_ref == eb["grantRef"].as_str().unwrap() && b.epoch == eb["epoch"].as_i64().unwrap() && b.nonce == eb["nonce"].as_str().unwrap());
            if !ok {
                bad.push(format!("{name}: verifier was not handed {eb}"));
            }
        }
    }
    assert!(pq_seen >= 3, "only {pq_seen} vectors exercised a supported post-quantum suite");
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The `passport_hardware_vectors` table: hardware-rooted passports whose evidence is verified by a REAL vendor verifier
/// built from the row's `hardware_verifier` {vendor, config, evidence} through the crate's default-verifier option.
/// The test fails (it never skips) when the table is missing from the vector file.
#[test]
fn passport_hardware_vectors() {
    let doc = load("passport-vectors.json");
    let rows = doc.get("passport_hardware_vectors").and_then(|v| v.as_array()).expect("passport-vectors.json has no passport_hardware_vectors table (regenerate the vectors)");
    assert!(rows.len() >= 40, "only {} hardware vectors", rows.len());
    let mut bad = Vec::new();
    let mut vendors = std::collections::BTreeSet::new();
    for v in rows {
        let name = v["name"].as_str().unwrap();
        let hv = &v["hardware_verifier"];
        let vendor = hv["vendor"].as_str().expect("vendor");
        vendors.insert(vendor.to_string());
        let verifier = match atlas_pca::attest::verifier_from_config(vendor, &hv["config"]) {
            Ok(x) => x.with_evidence(hv["evidence"].clone()),
            Err(e) => {
                bad.push(format!("{name}: the vendor verifier was not constructible: {e}"));
                continue;
            }
        };
        let issuers: Vec<String> = v["trustedIssuers"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let revoked: Vec<String> = v["revoked"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        let f = |id: &str, _: &str, _: &str| -> Result<bool, ()> { Ok(revoked.iter().any(|r| r == id)) };
        let o = PassportOptions {
            trusted_issuers: &issuers,
            now_ms: v["now"].as_i64().unwrap(),
            clock_skew_ms: v.get("clockSkewMs").and_then(|x| x.as_i64()),
            max_evidence_age_ms: v.get("maxEvidenceAgeMs").and_then(|x| x.as_i64()),
            subject: v.get("subject").and_then(|x| x.as_str()),
            pq_pins: None,
            attest: None,
            default_verifier: Some(&verifier),
            revoked: Some(&f),
        };
        let got = verify_passport(&v["signed"], &o);
        let want = if v["expect"]["ok"].as_bool() == Some(true) { Ok(()) } else { Err(v["expect"]["reason"].as_str().unwrap()) };
        if got != want {
            bad.push(format!("{name}: got {got:?} want {want:?}"));
        }
    }
    assert_eq!(vendors.len(), 5, "every vendor must be exercised: {vendors:?}");
    assert!(bad.is_empty(), "{bad:#?}");
}

fn hw_opts<'a>(
    issuers: &'a [String],
    now_ms: i64,
    revoked: &'a dyn Fn(&str, &str, &str) -> Result<bool, ()>,
    attest: Option<AttestFn<'a>>,
    default_verifier: Option<&'a atlas_pca::attest::HardwareVerifier>,
) -> PassportOptions<'a> {
    PassportOptions { trusted_issuers: issuers, now_ms, clock_skew_ms: None, max_evidence_age_ms: None, subject: None, pq_pins: None, attest, default_verifier, revoked: Some(revoked) }
}

/// An integrator-supplied `attest` wins over the default verifier, and a hardware-rooted passport with neither is refused.
#[test]
fn integrator_attest_wins_over_the_default_verifier() {
    let doc = load("passport-vectors.json");
    let rows = doc["passport_vectors"].as_array().unwrap();
    let hw = rows.iter().find(|v| v["name"].as_str() == Some("hardware-ok")).expect("the stub hardware-ok row");
    let issuers: Vec<String> = hw["trustedIssuers"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    let now = hw["now"].as_i64().unwrap();
    let none = |_: &str, _: &str, _: &str| -> Result<bool, ()> { Ok(false) };
    // a default verifier that can never accept: no evidence is configured, so it answers a denial
    let default = atlas_pca::attest::verifier_from_config("nvidia-gpu-spdm", &serde_json::json!({ "rootSpkiSha256": ["00"], "policy": { "measurements": { "0": "00" } } })).expect("config");
    let measured = hw["hardware"]["measured"].as_object().cloned();
    let stub = move |_: &Value, _: &PassportBinding| -> Result<PassportAttestation, ()> { Ok(PassportAttestation { ok: true, bound: true, measured: measured.clone() }) };
    assert_eq!(verify_passport(&hw["signed"], &hw_opts(&issuers, now, &none, None, None)), Err("hardware_verifier_missing"));
    assert_eq!(verify_passport(&hw["signed"], &hw_opts(&issuers, now, &none, Some(&stub), Some(&default))), Ok(()));
    assert_eq!(verify_passport(&hw["signed"], &hw_opts(&issuers, now, &none, None, Some(&default))), Err("hardware_attestation_failed"));
}
