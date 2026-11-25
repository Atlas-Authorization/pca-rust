//! Differential replay of the remaining sandbox pieces against the TypeScript reference (test-data/ref-sandbox.json.gz, cases
//! `handles`, `signRuntimeClaim`, `verifiedRuntimeClass`, `passportDigest`, `evidenceDigest`, `buildTool`, `buildProbeTool`,
//! `referenceComponentWat`, `moduleConsts`; the runtime claim domain is the `DOMAIN` member of `moduleConsts`). A reference throw
//! only requires a refusal. Executors by verb are fixed as in the generator: bytes [1,2,3], echo = JSON of the operation, throw,
//! notbytes. Keys are derived from sha256("atlas-pca-conformance/" + label). Skipped: none besides cases holding a lone surrogate.
mod common;
use atlas_pca::{AuthorizedOperation, Operation};
use atlas_pca::sandbox_claims::*;
use atlas_pca::sandbox_handles::*;
use atlas_pca::sandbox_receipts::ReceiptLog;
use atlas_pca::sandbox_reference::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const FNS: [&str; 9] = [
    "handles",
    "signRuntimeClaim",
    "verifiedRuntimeClass",
    "passportDigest",
    "evidenceDigest",
    "buildTool",
    "buildProbeTool",
    "referenceComponentWat",
    "moduleConsts",
];

fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into()
}
fn bytes_json(b: &[u8]) -> Value {
    json!({"$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)})
}

fn executors() -> HashMap<String, Executor> {
    let mut m: HashMap<String, Executor> = HashMap::new();
    m.insert("fs.read".into(), Box::new(|_| Ok(vec![1, 2, 3])));
    m.insert("fs.echo".into(), Box::new(|op| Ok(atlas_pca::serde_json::to_string(op).unwrap().into_bytes())));
    m.insert("fs.throw".into(), Box::new(|_| Err("boom".into())));
    m.insert("fs.notbytes".into(), Box::new(|_| Err("nope".into())));
    m
}

fn handles(spec: &Value) -> Value {
    let clock = Arc::new(Mutex::new(0f64));
    let (c1, c2) = (clock.clone(), clock.clone());
    let log = ReceiptLog::new(Some(Box::new(move || *c1.lock().unwrap())), None);
    let mut t = HandleTable::new(spec["cls"].as_str().unwrap(), log, executors(), Some(Box::new(move || *c2.lock().unwrap())));
    let mut outs = vec![];
    let err = || json!({"$err": true});
    for st in spec["steps"].as_array().unwrap() {
        let index = st["index"].as_f64().unwrap_or(f64::NAN);
        let out = match st["op"].as_str().unwrap() {
            "now" => {
                *clock.lock().unwrap() = st["t"].as_f64().unwrap();
                Value::Null
            }
            "mint" => {
                let o = &st["operation"];
                let operation = Operation::new(o["verb"].as_str().unwrap_or(""), o["resource"].as_str().unwrap_or(""), o["params"].clone());
                let bind = match st.get("bind") {
                    None => {
                        let mut b = o.clone();
                        b["id"] = st.get("id").cloned().unwrap_or(json!("op-h"));
                        b
                    }
                    Some(b) => b.clone(),
                };
                let bound = (st.get("allow") != Some(&json!(false)) && bind.is_object()).then(|| AuthorizedOperation {
                    verb: bind["verb"].as_str().unwrap_or("").into(),
                    resource: bind["resource"].as_str().unwrap_or("").into(),
                    params_digest: atlas_pca::hash_canonical_strict(&bind["params"]).unwrap_or_default(),
                    id: bind.get("id").and_then(Value::as_str).unwrap_or("op").into(),
                });
                let opts = st.get("opts").cloned().unwrap_or(json!({}));
                let mo = MintOptions {
                    uses: opts.get("uses").and_then(Value::as_f64),
                    expires_at: opts.get("expiresAt").and_then(Value::as_f64),
                    requires: opts.get("requires").and_then(Value::as_str).map(String::from),
                };
                t.mint(bound.as_ref(), &operation, &mo).map(|i| json!(i)).unwrap_or_else(|_| err())
            }
            "attenuate" => {
                let n = &st["narrower"];
                t.attenuate(index, n.get("uses").and_then(Value::as_f64), n.get("expiresAt").and_then(Value::as_f64))
                    .map(|i| json!(i))
                    .unwrap_or_else(|_| err())
            }
            "revoke" => {
                t.revoke(index);
                Value::Null
            }
            "use" => use_result_json(&t.use_handle(index)),
            "verbOf" => t.verb_of(index).map(Value::from).unwrap_or(Value::Null),
            _ => json!(t.size()),
        };
        outs.push(out);
    }
    json!({"outs": outs, "log": t.log().entries})
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "handles" => Ok(handles(&a[0])),
        "moduleConsts" => Ok(module_consts()),
        "signRuntimeClaim" => {
            let key = match a[0].as_str() {
                Some(l) => seed(l).to_vec(),
                None => vec![0u8; a[0]["short"].as_u64().ok_or("bad key")? as usize],
            };
            let public = common::b64d(&atlas_pca::grants::signer_of(&seed(a[1].as_str().ok_or("bad pub")?)));
            sign_runtime_claim(&key, &public, &a[2])
        }
        "verifiedRuntimeClass" => Ok(json!(verified_runtime_class_trust(&a[0], &a[1]))),
        "passportDigest" => passport_digest(&a[0]).map(Value::from),
        "evidenceDigest" => evidence_digest(&a[0]).map(Value::from),
        "buildTool" => build_tool(&a[0]).map(|b| bytes_json(&b)),
        "buildProbeTool" => Ok(bytes_json(&build_probe_tool(a.first().and_then(Value::as_i64).map(|n| n as i32)))),
        "referenceComponentWat" => Ok(json!(reference_component_wat(a.first()))),
        _ => Err("skip".into()),
    }
}

#[test]
fn sandbox_rest_vectors() {
    let cases = common::ref_cases("sandbox");
    let (mut bad, mut ran) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if !FNS.contains(&f) || common::has_lone(&c["args"]) {
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
    // 200 corpus cases of these functions, one carries a lone surrogate
    assert_eq!(ran, 199, "cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}
