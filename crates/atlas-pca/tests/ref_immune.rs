//! Differential replay of the behavioral immune system's adaptation, no-widen check, digests, signed tightening proposals and durable
//! store against the TypeScript reference (test-data/ref-immune-java.json.gz, 559 cases). Guardian keys come from the generator's seed
//! scheme (seed label "immune/<label>" = sha256("atlas-pca-conformance/immune/<label>")); the pinned guardian "@g" is the public key of
//! the seed labelled g. A reference throw only requires a refusal. Skipped (counted, must stay under 10%): cases with a lone surrogate.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::immune::*;
use atlas_pca::kv::{AtomicKv, MemoryAtomicKv};
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn seed(label: &str) -> [u8; 32] {
    let h = Sha256::digest(format!("atlas-pca-conformance/immune/{label}").as_bytes());
    let mut o = [0u8; 32];
    o.copy_from_slice(&h);
    o
}

/// opts whose pinned guardian is "@g" carry the public key of seed g instead.
fn pin(opts: &Value) -> Value {
    let mut o = opts.clone();
    if o.get("guardian").and_then(Value::as_str) == Some("@g") {
        o["guardian"] = Value::String(KeyPair::from_seed(&seed("g")).public.clone());
    }
    o
}

fn store(a: &[Value]) -> Result<Value, String> {
    let kv = MemoryAtomicKv::new();
    let subject = a[0].as_str().ok_or("subject")?;
    let st = ImmuneStore::new(&kv, subject);
    let mut out = Vec::new();
    for op in a[1].as_array().ok_or("ops")? {
        let op = op.as_array().ok_or("op")?;
        let r: Result<Value, String> = match op[0].as_str().unwrap_or("") {
            "seed" => {
                let v = op[1].clone();
                kv.update(&format!("immune/state/{subject}"), &mut |_| Some(v.clone())).map(|_| Value::Null).map_err(|e| e.0)
            }
            "get" => st.get(),
            "observe" => st.observe(&op[1]),
            "lastEpoch" => st.last_epoch().map(|e| json!(e)),
            "apply" => st.apply(&op[1], &op[2], &pin(&op[3])),
            n => panic!("unknown op {n}"),
        };
        out.push(r.unwrap_or_else(|_| json!({ "$err": "Error" })));
    }
    Ok(Value::Array(out))
}

fn run(name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "adapt" => adapt(&a[0], &a[1]),
        "noWidenViolation" => no_widen_violation(&a[0], &a[1]).map(|v| v.map_or(Value::Null, Value::String)),
        "policyDigest" => Ok(Value::String(policy_digest(&a[0]))),
        "immuneStateDigest" => Ok(Value::String(immune_state_digest(&a[0]))),
        "issueTighteningProposal" => issue_tightening_proposal(&a[0], &a[1], &a[2], &a[3], &seed(a[4].as_str().ok_or("label")?)),
        "applyTightening" => Ok(apply_tightening(&a[0], &a[1], &pin(&a[2]))),
        "store" => store(a),
        n => panic!("unknown fn {n}"),
    }
}

#[test]
fn immune_vectors() {
    let cases = common::ref_cases("immune-java");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let name = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap().clone();
        let got = std::panic::catch_unwind(|| run(name, &args)).unwrap_or_else(|_| Err("panic".into()));
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
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
