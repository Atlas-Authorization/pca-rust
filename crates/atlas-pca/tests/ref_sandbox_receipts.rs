//! Differential replay of the sandbox runtime-class order and the receipt hash chain against the TypeScript reference
//! (test-data/ref-sandbox.json.gz, cases `satisfiesRuntimeClass`, `receiptLog`, `verifyReceiptChain`). A reference throw only
//! requires a refusal. The host signature of the oracle is `sig:<digest>`.
mod common;
use atlas_pca::sandbox_receipts::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn receipt_log(spec: &Value) -> Value {
    let clock = Arc::new(Mutex::new(0f64));
    let c2 = clock.clone();
    let sign: Option<Box<dyn Fn(&str) -> String + Send>> = (spec["sign"] == true).then(|| Box::new(|d: &str| format!("sig:{d}")) as _);
    let mut log = ReceiptLog::new(Some(Box::new(move || *c2.lock().unwrap())), sign);
    let mut outs = vec![];
    for a in spec["appends"].as_array().unwrap() {
        *clock.lock().unwrap() = a["t"].as_f64().unwrap();
        outs.push(match log.append(a["rc"].as_str().unwrap(), &a["body"]) {
            Ok(r) => r,
            Err(_) => json!({"$err": true}),
        });
    }
    Value::Array(outs)
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "satisfiesRuntimeClass" => Ok(json!(matches!((a[0].as_str(), a[1].as_str()), (Some(x), Some(y)) if satisfies_runtime_class(x, y)))),
        "receiptLog" => Ok(receipt_log(&a[0])),
        "verifyReceiptChain" => {
            let tag = |d: &str, s: &str| s == format!("sig:{d}");
            verify_receipt_chain(&a[0], if a[1] == "tag" { Some(&tag) } else { None })
        }
        _ => Err("skip".into()),
    }
}

#[test]
fn sandbox_receipts_vectors() {
    let cases = common::ref_cases("sandbox");
    let (mut bad, mut ran) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if !["satisfiesRuntimeClass", "receiptLog", "verifyReceiptChain"].contains(&f) || common::has_lone(&c["args"]) {
            continue;
        }
        ran += 1;
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
    assert!(ran > 400, "only {ran} cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}
