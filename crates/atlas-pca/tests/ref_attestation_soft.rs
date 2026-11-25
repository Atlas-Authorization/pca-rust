//! Differential replay of test-data/ref-attestation-soft.json.gz (written by the TypeScript reference): the report-data binding, the dev
//! attestor and its documents (ed25519, ML-DSA and the hybrids), the registry, the bounded nonce store, the entropy gate, the agent-binding
//! match, the total verifier (software and hardware paths), the hook, the multi-root verifier and evidence anchoring. Every function of the
//! corpus has a handler and the per-function totals are asserted. A reference refusal must be a refusal here. A reason that starts with
//! `attestation verification error (fail closed):` carries the reference's own exception text after the colon: only the prefix is compared.
//! The 2 verdicts the reference accepts only through its legacy unbound post-quantum opt-out are asserted REFUSED (that option is not
//! offered). 4 cases carry a non-finite number inside a document, claim or evidence that the reference hashes: not a JSON value, not run.
mod common;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::attestation::*;
use atlas_pca::ledger_store::TransparencyLedger;
use atlas_pca::serde_json::{json, Map, Value};
use base64::Engine;
use common::replay::{skip, thrown};

const FAIL_CLOSED: &str = "attestation verification error (fail closed):";

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// A number: a JSON number, or `{"$num": "NaN" | "Infinity" | "-Infinity"}`; anything else is NaN.
fn double(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        _ => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
}

fn has_marker(v: &Value) -> bool {
    match v {
        Value::Object(m) => (m.len() == 1 && m.contains_key("$num")) || m.values().any(has_marker),
        Value::Array(a) => a.iter().any(has_marker),
        _ => false,
    }
}

fn text(r: Result<String, String>) -> Value {
    r.map(Value::String).unwrap_or_else(thrown)
}

fn key_of(v: &Value) -> KeyPair {
    KeyPair::from_seed_b64u(v["$bytes"].as_str().unwrap()).unwrap()
}

/// `{alg, pqSeed?}` -> the PQ key pair of its seed (the reference's ML-DSA-65 key from a 32-byte seed).
fn pq_of(spec: &Value) -> Option<PqKeyPair> {
    let seed = spec.get("pqSeed")?;
    Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(seed["$bytes"].as_str().unwrap())).unwrap())
}

fn hw(spec: &Value) -> Option<Arc<HardwareVerifierFn>> {
    if spec.is_null() {
        return None;
    }
    let (throws, result) =
        (spec.get("throws").and_then(Value::as_str).map(str::to_string), spec.get("result").cloned().unwrap_or(Value::Null));
    Some(Arc::new(move |_: &Value| match &throws {
        Some(m) => Err(m.clone()),
        None => Ok(result.clone()),
    }))
}

struct ConstStore(bool);

impl AttestationNonceStore for ConstStore {
    fn consume(&self, _nonce: &str) -> bool {
        self.0
    }
}

fn clock_of(t: &Arc<Mutex<f64>>) -> Box<dyn Fn() -> f64 + Send + Sync> {
    let t = t.clone();
    Box::new(move || *t.lock().unwrap())
}

fn nonce_store(a: &[Value]) -> Value {
    let max = if a[0].is_null() { DEFAULT_MAX_NONCES } else { double(&a[0]) };
    let retention = a[1].get("retentionMs").filter(|v| !v.is_null()).map(double);
    let t = Arc::new(Mutex::new(0.0));
    let store = match MemoryNonceStore::new(max, retention, Some(clock_of(&t))) {
        Ok(s) => s,
        Err(e) => return thrown(e),
    };
    Value::Array(
        a[2].as_array()
            .unwrap()
            .iter()
            .map(|op| match op[0].as_str().unwrap() {
                "clock" => {
                    *t.lock().unwrap() = double(&op[1]);
                    Value::Null
                }
                _ => json!(op[1].as_str().is_some_and(|n| store.consume(n))),
            })
            .collect(),
    )
}

fn hook_cases(a: &[Value]) -> Value {
    let op = a[0].as_object().unwrap();
    let now = double(&op["now"]);
    let mut rest = op.clone();
    for k in ["store", "storeConsume", "hardware", "docs", "binding", "now"] {
        rest.remove(k);
    }
    let mut hooks = AttestationHooks::default();
    hooks.resolve_document = Some(attestation_registry(op.get("docs").unwrap_or(&json!([]))));
    hooks.now = Some(Arc::new(move || now));
    hooks.hardware = op.get("hardware").and_then(hw);
    if let Some(store) = op.get("store").filter(|s| s.is_object()) {
        let max = store.get("max").map_or(DEFAULT_MAX_NONCES, double);
        let t = Arc::new(Mutex::new(now));
        match MemoryNonceStore::new(max, store.get("retentionMs").map(double), Some(clock_of(&t))) {
            Ok(s) => hooks.nonce_store = Some(Arc::new(s)),
            Err(e) => return thrown(e),
        }
    }
    if let Some(c) = op.get("storeConsume").and_then(Value::as_bool) {
        hooks.nonce_store = Some(Arc::new(ConstStore(c)));
    }
    match op.get("binding") {
        Some(Value::String(_)) => hooks.expected_binding = Some(Arc::new(|_: &Value| Err("boom".to_string()))),
        Some(b) => {
            let by_nonce = b["byNonce"].as_object().cloned().unwrap_or_default();
            hooks.expected_binding = Some(Arc::new(move |ctx: &Value| {
                let key = ctx
                    .get("pcactn")
                    .and_then(|p| p.get("attestation"))
                    .and_then(|a| a.get("quote_digest"))
                    .map_or_else(|| "undefined".to_string(), |q| q.as_str().map_or_else(|| q.to_string(), str::to_string));
                Ok(by_nonce.get(&key).cloned())
            }));
        }
        None => {}
    }
    let verify = create_attestation_verifier(&Value::Object(rest), hooks);
    Value::Array(a[1].as_array().unwrap().iter().map(|c| verify(c)).collect())
}

fn multi_root(a: &[Value]) -> Value {
    let pol = &a[0];
    let mut roots = Vec::new();
    for r in pol["roots"].as_array().unwrap() {
        let verifier = hw(&r["hw"]).unwrap_or_else(|| Arc::new(|_: &Value| Err("verifier is undefined".to_string())));
        roots.push(AttestationRoot {
            id: r["id"].clone(),
            verifier,
            required: r.get("required") == Some(&json!(true)),
            suite: r.get("suite").and_then(Value::as_str).map(str::to_string),
        });
    }
    let verify = match create_multi_root_verifier(double(&pol["threshold"]), roots) {
        Ok(v) => v,
        Err(e) => return thrown(e),
    };
    if a[1].is_null() {
        return json!({"built": true});
    }
    verify(&a[1]).unwrap_or_else(thrown)
}

fn anchor(a: &[Value]) -> Value {
    let op = &a[1];
    let mut ledger = (op["ledger"] == json!("ok"))
        .then(|| TransparencyLedger::from_entries(Vec::new()).with_principal(op["principal"].as_str().unwrap_or("")));
    for i in 0..op["preload"].as_u64().unwrap_or(0) {
        ledger.as_mut().unwrap().append_commitment(&format!("c{i}")).unwrap();
    }
    let guardian = op.get("guardianSeed").map(key_of);
    let opts = AnchorOptions {
        guardian: guardian.as_ref(),
        instance_id: op["instanceId"].as_str(),
        now: op.get("now").map(double),
        required: op["required"] == json!(true),
        ..Default::default()
    };
    anchor_attestation_evidence(&a[0], ledger.as_mut(), &opts).unwrap_or_else(thrown)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "ATTEST_BIND_DOMAIN": ATTEST_BIND_DOMAIN,
            "MAX_ATTESTATION_AGE_MS": MAX_ATTESTATION_AGE_MS,
            "DEFAULT_NONCE_RETENTION_MS": DEFAULT_NONCE_RETENTION_MS,
            "MIN_ATTESTATION_NONCE_BYTES": MIN_ATTESTATION_NONCE_BYTES,
            "ATTEST_ANCHOR_DOMAIN": ATTEST_ANCHOR_DOMAIN,
        }),
        "attestationBinding" => attestation_binding(&a[0]).map(|b| json!({"$bytes": b64u(&b)})).unwrap_or_else(thrown),
        "attestationBindingB64u" => text(attestation_binding_b64u(&a[0])),
        "attest" if has_marker(&a[2]) => skip("a non-finite number is not a JSON value"),
        "attest" | "attestorPublicKey" => {
            let pq = pq_of(&a[1]);
            let suite = Suite { alg: a[1].get("alg").and_then(Value::as_str), pq: pq.as_ref() };
            match create_dev_attestor(key_of(&a[0]), suite) {
                Err(e) => thrown(e),
                Ok(at) if f == "attestorPublicKey" => json!(at.public_key),
                Ok(at) => at.attest(&a[2]).unwrap_or_else(thrown),
            }
        }
        "attestationDigest" if has_marker(&a[0]) => skip("a non-finite number is not a JSON value"),
        "attestationDigest" => text(attestation_digest(&a[0])),
        "registry" => {
            let r = attestation_registry(&a[0]);
            Value::Array(
                a[1].as_array()
                    .unwrap()
                    .iter()
                    .map(|q| r(&json!({"pcactn": {"attestation": {"quote_digest": q}}})).unwrap_or(Value::Null))
                    .collect(),
            )
        }
        "nonceStore" => nonce_store(a),
        "nonceEntropyOk" => json!(nonce_entropy_ok(&a[0], Some(&a[1]).filter(|m| !m.is_null()))),
        "requiresAttestation" => json!(requires_attestation(&a[0])),
        "nonceBinds" => json!(nonce_binds(&a[0], &a[1])),
        "matchAgentBinding" => match_agent_binding(&a[0], &a[1]).map(|r| r.map_or(Value::Null, Value::String)).unwrap_or_else(thrown),
        "verifyAttestation" => {
            let mut input: Map<String, Value> = a[0].as_object().unwrap().clone();
            let verifier = hw(&input.remove("hardware").unwrap_or(Value::Null));
            if input.get("document") == Some(&Value::Null) {
                input.remove("document");
            }
            if input.get("document").is_some_and(has_marker) {
                return skip("a non-finite number is not a JSON value");
            }
            verify_attestation(&Value::Object(input), verifier.as_deref())
        }
        "attestationHook" => hook_cases(a),
        "multiRoot" => multi_root(a),
        "attestationEvidenceDigest" if has_marker(&a[0]) => skip("a non-finite number is not a JSON value"),
        "attestationEvidenceDigest" => text(attestation_evidence_digest(&a[0])),
        "anchorEvidence" => anchor(a),
        other => panic!("unhandled corpus function {other}"),
    }
}

/// The reference's own exception text after the fail-closed prefix is not compared.
fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| match (k.as_str(), x.as_str()) {
                    ("reason", Some(r)) if r.starts_with(FAIL_CLOSED) => (k.clone(), json!(FAIL_CLOSED)),
                    _ => (k.clone(), norm(x)),
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        other => other.clone(),
    }
}

fn differs(want: &Value, got: &Value) -> bool {
    if want.get("$throws").is_some() {
        got.get("$throws").is_none()
    } else {
        atlas_pca::canonicalize(&norm(want)) != atlas_pca::canonicalize(&norm(got))
    }
}

#[test]
fn attestation_soft_replay() {
    let cases = common::ref_cases_seeded("attestation-soft");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("matchAgentBinding", 170),
        ("verifyAttestation", 91),
        ("nonceEntropyOk", 32),
        ("requiresAttestation", 29),
        ("attestationBinding", 27),
        ("attestationBindingB64u", 27),
        ("multiRoot", 27),
        ("nonceStore", 23),
        ("attestationHook", 23),
        ("attest", 18),
        ("attestationEvidenceDigest", 11),
        ("anchorEvidence", 10),
        ("nonceBinds", 8),
        ("attestationDigest", 6),
        ("registry", 6),
        ("attestorPublicKey", 3),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 512);

    // the reference accepts a post-quantum document without a pin only through its legacy unbound opt-out, which is not offered here
    let (unbound, rest): (Vec<Value>, Vec<Value>) =
        cases.into_iter().partition(|c| c["args"].to_string().contains("allowUnboundPq") && c["out"]["ok"] == json!(true));
    assert_eq!(unbound.len(), 2, "reference acceptances through the unbound opt-out");
    for c in &unbound {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        assert_eq!(got["ok"], json!(false), "{} must be refused", c["name"]);
    }

    let (mut skipped, mut bad) = (0usize, Vec::new());
    for c in &rest {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        if got.get("$skip").is_some() {
            skipped += 1;
        } else if differs(&c["out"], &got) {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert_eq!(skipped, 4, "cases not run (a non-finite number in a hashed value)");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), rest.len(), bad.join("\n"));
}
