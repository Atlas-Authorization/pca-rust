//! Differential replay of the attested orchestration harness (measurement, allowlisting verifier, plan-inclusion / taint / budget
//! gated signing) against the TypeScript reference (test-data/ref-harness.json.gz). A reference throw only requires a refusal.
//! The agent key of a scenario is Ed25519 seed sha256("atlas-pca-conformance/" + label); the clock is constant between `now` steps and
//! the k-th nonce is `n<k>`. A constructor refusal is the reference's `{$err: true}`.
mod common;
use atlas_pca::harness::*;
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

fn seed_of(label: &str) -> [u8; 32] {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into()
}

fn scenario(s: &Value) -> Result<Value, String> {
    let op = &s["opts"];
    let clock = Arc::new(Mutex::new(1_800_000_000_000f64));
    let c2 = clock.clone();
    let mut k = 0usize;
    let plan = op["plan"].as_array().ok_or("plan")?.clone();
    let mut o = HarnessOptions::new(
        op["grant"].clone(),
        seed_of(op["label"].as_str().ok_or("label")?),
        plan,
        op["audience"].as_str().ok_or("audience")?,
        op["budget"].clone(),
    );
    o.chain = op.get("chain").and_then(Value::as_array).cloned();
    o.policy = op.get("policy").cloned();
    o.base_risk = op.get("baseRisk").cloned();
    o.now = Some(Box::new(move || *c2.lock().unwrap()));
    o.ttl_ms = op.get("ttlMs").and_then(Value::as_i64);
    o.measurement_manifest = op.get("manifest").and_then(Value::as_array).map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
    o.nonce = Some(Box::new(move || {
        let n = format!("n{k}");
        k += 1;
        n
    }));
    o.attestation = op.get("attestation").cloned();
    let mut h = Harness::new(o)?;
    let mut outs = vec![];
    for st in s["steps"].as_array().unwrap() {
        if st["op"] == "now" {
            *clock.lock().unwrap() = st["t"].as_f64().unwrap();
            outs.push(Value::Null);
            continue;
        }
        let orc = st["oracle"].clone();
        outs.push(h.step(move || match orc["kind"].as_str().unwrap() {
            "throw" => Err(orc["msg"].as_str().unwrap().to_string()),
            "bad" => Ok(orc["v"].clone()),
            _ => Ok(orc["c"].clone()),
        }));
    }
    let mut m = Map::new();
    m.insert("steps".into(), Value::Array(outs));
    m.insert("budget".into(), h.budget());
    m.insert("counter".into(), json!(h.counter()));
    m.insert("planRoot".into(), json!(h.plan_root()));
    m.insert("measurement".into(), json!(h.harness_measurement()?));
    Ok(Value::Object(m))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "consts" => Ok(json!({"HARNESS_VERSION": HARNESS_VERSION, "HARNESS_MODEL_ID": HARNESS_MODEL_ID, "ENFORCED_CHECKS": ENFORCED_CHECKS})),
        "computeHarnessMeasurement" => compute_harness_measurement(&a[0], &a[1], &a[2]).map(Value::String),
        "harnessAttest" => Ok(create_harness_attestation_verifier(&a[0])?(&a[1])),
        "harness" => match scenario(&a[0]) {
            Ok(v) => Ok(v),
            Err(e) if e.starts_with("Harness:") || ["plan", "label", "audience"].contains(&e.as_str()) => Ok(json!({"$err": true})),
            Err(e) => Err(e),
        },
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn harness_vectors() {
    let cases = common::ref_cases("harness");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
