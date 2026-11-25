//! Differential replay of the testing kit (acceptance constants and route mapping, fake verifier, expect helpers, tamper, in-memory
//! state store) against the TypeScript reference (test-data/ref-testing.json.gz). A reference throw only requires a refusal.
//! Not covered: the agent factories and the per-adapter acceptance matrix runner (not replayable as vectors).
mod common;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::testing::*;

fn mutation(rec: &mut atlas_pca::serde_json::Map<String, Value>, m: &Value) -> Result<(), String> {
    let op = m["op"].as_str().ok_or("op")?;
    if op == "none" {
        return Ok(());
    }
    let path: Vec<&str> = m["path"].as_array().ok_or("path")?.iter().map(|p| p.as_str().unwrap()).collect();
    let (last, parents) = path.split_last().ok_or("empty path")?;
    let mut cur = rec;
    for p in parents {
        cur = cur.get_mut(*p).and_then(Value::as_object_mut).ok_or_else(|| format!("Cannot set properties of undefined (setting '{last}')"))?;
    }
    match op {
        "set" => {
            cur.insert((*last).to_string(), m["value"].clone());
        }
        _ => {
            cur.remove(*last);
        }
    }
    Ok(())
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let null = Value::Null;
    let o = a.get(1).unwrap_or(&null);
    match f {
        "consts" => Ok(json!({"aud": ADAPTER_ACCEPTANCE_AUDIENCE, "expected": adapter_acceptance_expected()})),
        "acceptanceOperation" => acceptance_operation(&a[0]).map(|o| o.unwrap_or(Value::Null)),
        "fakeVerifyAllow" => fake_verify(&a[0], o).map(|v| json!(v.allow)),
        "expectVerifies" => expect_verifies(&a[0], o).map(|v| json!(v.allow)),
        "expectDenied" => expect_denied(&a[0], o).map(|v| json!(v.allow)),
        "tamper" => tamper(a[0].as_str().ok_or("encoded")?, |rec| mutation(rec, &a[1])).map(Value::String),
        "memorySession" => {
            let mut s = memory_state_store();
            let mut out = vec![];
            for op in a[0].as_array().unwrap() {
                match op[0].as_str().unwrap() {
                    "get" => out.push(s.get(op[1].as_str().unwrap()).cloned().unwrap_or(Value::Null)),
                    _ => s.put(op[1].as_str().unwrap(), op[2].clone()),
                }
            }
            Ok(Value::Array(out))
        }
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn testing_vectors() {
    let cases = common::ref_cases("testing");
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
