//! Differential replay of test-data/ref-attest-puf.json.gz (written by the TypeScript reference): the repetition-code fuzzy extractor, the
//! simulated PUF, the TPM endorsement-key provider over an injected runner, enrollment under every derived suite, the device attestor, the
//! enrollment registry and the verifier. Every function of the corpus has a handler and the per-function totals are asserted. A
//! reference refusal must be a refusal here; the TPM provider's own messages and every verifier reason are compared exactly. The corpus
//! carries the digest of the extracted key, never the key.
mod common;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use atlas_pca::attest::puf::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::thrown;
use sha2::{Digest, Sha256};

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(text(&v["$bytes"]))
}

fn enc(b: &[u8]) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn key_sha(k: &[u8]) -> String {
    hex(&Sha256::digest(k))
}

/// `{id, seed, length, flip?}`: the simulated PUF.
fn sim(spec: &Value) -> SimulatedPuf {
    let flips: Vec<i64> =
        spec.get("flip").and_then(Value::as_array).map(|f| f.iter().filter_map(Value::as_i64).collect()).unwrap_or_default();
    create_simulated_puf(text(&spec["id"]), &common::b64d(text(&spec["seed"])), spec["length"].as_u64().unwrap() as usize, &flips)
}

/// The `randomBytes` callback: its first call returns `r1`, its second `r2`, each cut to the requested length.
fn rand(r: &Value) -> impl FnMut(usize) -> Vec<u8> {
    let (r1, r2) = (bytes(&r[0]), bytes(&r[1]));
    let mut calls = 0;
    move |n| {
        let src = if calls == 0 { &r1 } else { &r2 };
        calls += 1;
        src[..n.min(src.len())].to_vec()
    }
}

/// The default challenge of the oracle's `tpmEk` cases.
fn default_challenge() -> Vec<u8> {
    Sha256::digest(b"attest-puf-oracle-randomness/challenge").to_vec()
}

fn tpm_case(c: &Value) -> Value {
    let calls: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let spec = c["run"].clone();
    let log = calls.clone();
    let runner: Arc<TpmCommandRunner> = Arc::new(move |cmd: &str, args: &[String]| {
        log.lock().unwrap().push(json!([cmd, args]));
        if spec == json!("undefined") {
            return Ok(None);
        }
        if let Some(e) = spec.get("$throws") {
            return Err(text(e).to_string());
        }
        Ok(Some(TpmCommandResult {
            status: spec.get("status").and_then(Value::as_i64),
            stdout: spec.get("stdout").filter(|s| s.get("$bytes").is_some()).map(bytes),
            stderr: spec.get("stderr").and_then(Value::as_str).map(String::from),
            error: spec.get("error").and_then(Value::as_str).map(String::from),
        }))
    });
    let out = TpmEkPufProvider::new(&c["opts"], runner).and_then(|p| {
        if text(&c["op"]) == "readEkPublic" {
            p.read_ek_public()
        } else {
            p.response(&c.get("challenge").map(bytes).unwrap_or_else(default_challenge))
        }
    });
    let mut v = match out {
        Ok(b) => json!({"ok": true, "value": enc(&b)}),
        Err(e) => json!({"ok": false, "error": e}),
    };
    v["calls"] = Value::Array(calls.lock().unwrap().clone());
    v
}

fn registry_case(c: &Value) -> Value {
    let mut r = create_puf_enrollment_registry(&c["enrollments"]);
    let out: Vec<Value> = c["ops"]
        .as_array()
        .unwrap()
        .iter()
        .map(|op| {
            let (k, v) = op.as_object().unwrap().iter().next().unwrap();
            match k.as_str() {
                "register" => {
                    r.register(v);
                    Value::Null
                }
                "lookup" => r.lookup(text(v)).unwrap_or(Value::Null),
                "revoke" => {
                    r.revoke(text(v));
                    Value::Null
                }
                _ => json!(r.is_revoked(text(v))),
            }
        })
        .collect();
    Value::Array(out)
}

fn verify_case(sc: &Value) -> Value {
    let policy = &sc["config"]["policy"];
    let mut cfg_policy = json!({"measurements": policy["measurements"]});
    if let Some(w) = policy.get("weightsMeasurements") {
        cfg_policy["weightsMeasurements"] = w.clone();
    }
    let mut cfg = json!({"policy": cfg_policy});
    if let Some(r) = sc["config"].get("requirePq") {
        cfg["requirePq"] = r.clone();
    }
    let mut seams = PufVerifierSeams::default();
    if sc["config"]["noResolveEnrollment"] != json!(true) {
        let enrollments: Vec<Value> = sc.get("enrollments").and_then(Value::as_array).cloned().unwrap_or_default();
        seams.resolve_enrollment = Some(Arc::new(move |id: &str, _: &Value, _: &Value| {
            Ok(enrollments.iter().rev().find(|e| e.get("providerId").and_then(Value::as_str) == Some(id)).cloned())
        }));
    }
    if sc["config"]["noEvidenceSeam"] != json!(true) {
        let ev = sc["evidence"].clone();
        seams.resolve_evidence = Some(Arc::new(move |_: &Value, _: &Value| Ok(Some(ev.clone()).filter(|e| !e.is_null()))));
    }
    if let Some(revoked) = sc.get("revoked").and_then(Value::as_array) {
        let revoked: Vec<String> = revoked.iter().map(|r| text(r).to_string()).collect();
        seams.is_revoked = Some(Arc::new(move |id: &str| Ok(revoked.iter().any(|r| r == id))));
    }
    if policy["identity"] == json!("custom") {
        seams.derive_identity = Some(Arc::new(|st: &Value, enr: &Value| {
            json!({
                "model_id": "m-custom",
                "weights_digest": st.get("weights_digest").filter(|w| !w.is_null()).cloned().unwrap_or(json!("")),
                "weights_measured": true,
                "runtime_measurement": st["measurement"],
                "operator": enr["providerId"],
            })
        }));
    }
    let verifier = match create_puf_verifier(&cfg, seams) {
        Ok(v) => v,
        Err(e) => return thrown(e),
    };
    let mut input = json!({"document": {}, "ctx": {}, "nowMs": sc["input"]["nowMs"]});
    if let Some(e) = sc["input"].get("expected") {
        input["expected"] = e.clone();
    }
    verifier(&input).unwrap_or_else(thrown)
}

fn build_case(a: &Value) -> Value {
    let mut cfg = json!({});
    if let Some(p) = a.get("policy") {
        cfg["policy"] = p.clone();
    }
    let mut seams = PufVerifierSeams::default();
    if a["noResolveEnrollment"] != json!(true) {
        seams.resolve_enrollment = Some(Arc::new(|_: &str, _: &Value, _: &Value| Ok(None)));
    }
    match create_puf_verifier(&cfg, seams) {
        Ok(_) => json!({"built": true}),
        Err(e) => thrown(e),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "PUF_EXTRACT_INFO": PUF_EXTRACT_INFO,
            "PUF_ATTEST_DOMAIN": PUF_ATTEST_DOMAIN,
            "PUF_KEY_BYTES": PUF_KEY_BYTES,
            "TPM_EK_PUF_DOMAIN": TPM_EK_PUF_DOMAIN,
        }),
        "repetitionCorrectionBound" => json!(repetition_correction_bound(a[0].as_f64().unwrap())),
        "simulatedPufResponse" => sim(&a[0]).response(&bytes(&a[1])).map(|b| enc(&b)).unwrap_or_else(thrown),
        "fuzzyEnroll" => fuzzy_enroll(&bytes(&a[0]), &a[1], &mut rand(&a[2]))
            .map(|e| json!({"keySha256": key_sha(&e.key), "helper": e.helper}))
            .unwrap_or_else(thrown),
        "fuzzyReproduce" => fuzzy_reproduce(&bytes(&a[0]), &a[1]).map(|k| json!({"keySha256": key_sha(&k)})).unwrap_or_else(thrown),
        "tpmEk" => tpm_case(&a[0]),
        "enrollPuf" => enroll_puf(&sim(&a[0]), &bytes(&a[1]), &a[2], &mut rand(&a[3])).unwrap_or_else(thrown),
        "pufAttest" => {
            let provider = sim(&a[0]);
            create_puf_attestor(&provider, &a[1]).and_then(|at| at.attest(&a[2])).unwrap_or_else(thrown)
        }
        "registry" => registry_case(&a[0]),
        "verifyPuf" => verify_case(&a[0]),
        "buildVerifier" => build_case(&a[0]),
        other => panic!("unhandled corpus function {other}"),
    }
}

/// The reference wraps most results as `{ok: true, value}`: compare the value (a `tpmEk` result carries `calls` too and is compared whole).
fn unwrap_want(c: &Value) -> Value {
    match c["out"].as_object() {
        Some(m) if m.len() == 2 && m.get("ok") == Some(&json!(true)) && m.contains_key("value") => m["value"].clone(),
        _ => c["out"].clone(),
    }
}

#[test]
fn puf_replay() {
    let mut cases = common::ref_cases_seeded("attest-puf");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(text(&c["fn"]).to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("fuzzyReproduce", 80),
        ("verifyPuf", 52),
        ("simulatedPufResponse", 30),
        ("tpmEk", 30),
        ("fuzzyEnroll", 23),
        ("pufAttest", 22),
        ("enrollPuf", 13),
        ("repetitionCorrectionBound", 12),
        ("registry", 10),
        ("buildVerifier", 5),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    for c in cases.iter_mut() {
        let w = unwrap_want(c);
        c["out"] = w;
    }
    common::replay::replay_cases("attest-puf", cases, 278, 0, run);
}
