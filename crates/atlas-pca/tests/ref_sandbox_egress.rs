//! Differential replay of the sandbox egress admission policy and the private-address check against the TypeScript reference
//! (test-data/ref-sandbox.json.gz, cases `egress` and `isPrivateAddress`; the other functions of that corpus belong to the
//! sandbox pieces this module does not carry: profiles, receipts, handles, runtime claims, reference tools).
//! NATIVE STRICTER: `is_private_address` follows the fixed rule (only 2000::/3 public, embedded IPv4 judged by its IPv4 rule, a zone
//! id private), so the old vectors that read an IPv6 literal outside that range as public are accepted as stricter, never the other
//! way round: a reference `true` must be `true` natively.
mod common;
use atlas_pca::{AuthorizedOperation, Operation};
use atlas_pca::sandbox_egress::*;
use atlas_pca::serde_json::{json, Value};
use std::sync::{Arc, Mutex};

fn unbytes(v: &Value) -> Vec<u8> {
    v["$bytes"].as_str().map(common::b64d).unwrap_or_default()
}

fn egress(spec: &Value) -> Value {
    let clock = Arc::new(Mutex::new(0f64));
    let c2 = clock.clone();
    let mut p = EgressPolicy::new(Box::new(move || *c2.lock().unwrap()));
    let mut outs = vec![];
    for st in spec["steps"].as_array().unwrap() {
        let out = match st["op"].as_str().unwrap() {
            "now" => {
                *clock.lock().unwrap() = st["t"].as_f64().unwrap();
                Value::Null
            }
            "admit" => {
                let b = &st["bind"];
                let bound = (st["allow"] == true && b.is_object()).then(|| AuthorizedOperation {
                    verb: b["verb"].as_str().unwrap().into(),
                    resource: b["resource"].as_str().unwrap().into(),
                    params_digest: atlas_pca::hash_canonical_strict(&b["params"]).unwrap(),
                    id: b.get("id").and_then(Value::as_str).unwrap_or("op").into(),
                });
                let o = &st["operation"];
                let op = Operation::new(o["verb"].as_str().unwrap_or(""), o["resource"].as_str().unwrap_or(""), o["params"].clone());
                let opts = st.get("opts").cloned().unwrap_or(json!({}));
                let tmpl = st["template"].clone();
                match p.admit(bound.as_ref(), &op, move |_| Some(tmpl), opts.get("uses"), opts.get("expiresAt").and_then(Value::as_f64)) {
                    Ok(()) => json!("ok"),
                    Err(_) => json!({"$err": true}),
                }
            }
            _ => {
                let r = &st["req"];
                match r["method"].as_str() {
                    None => json!({"$err": true}),
                    Some(m) => {
                        let url = match &r["url"] {
                            Value::String(u) => u.clone(),
                            Value::Null => "null".into(),
                            other => other.to_string(),
                        };
                        p.claim(m, &url, &unbytes(&r["body"])).to_json()
                    }
                }
            }
        };
        outs.push(out);
    }
    Value::Array(outs)
}

#[test]
fn sandbox_egress_vectors() {
    let cases = common::ref_cases("sandbox");
    let (mut bad, mut ran, mut stricter) = (Vec::new(), 0, 0);
    for c in &cases {
        match c["fn"].as_str().unwrap() {
            "isPrivateAddress" => {
                ran += 1;
                let Some(ip) = c["args"][0].as_str() else { continue };
                let got = is_private_address(ip);
                match c["out"].as_bool() {
                    Some(want) if want == got => {}
                    Some(false) if got => stricter += 1,
                    _ => bad.push(format!("isPrivateAddress({ip:?}) want {} got {got}", c["out"])),
                }
            }
            "egress" => {
                ran += 1;
                let got = egress(&c["args"][0]);
                // a url with a lone surrogate cannot be held in a Rust string: skipped by the loader sentinel
                if common::has_lone(&c["args"]) {
                    continue;
                }
                if atlas_pca::canonicalize(&got) != atlas_pca::canonicalize(&c["out"]) {
                    bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
                }
            }
            _ => {}
        }
    }
    assert!(ran > 200, "only {ran} cases replayed");
    assert!(stricter < 20, "{stricter} stricter-than-reference address cases");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}
