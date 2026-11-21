//! Differential replay of the deterministic invariants surface (keyPairFromSeed, buildChain with byte-identical signed caps,
//! worsen, consts) against the TypeScript reference (test-data/ref-invariants.json.gz). A reference throw only requires a refusal.
//! Skipped: the property functions and arbitraries (no property-testing library; not in the corpus).
mod common;
use atlas_pca::invariants::*;
use atlas_pca::serde_json::{json, Value};

/// Corpus `{"$bytes": b64u}` values to the plain b64u string the Rust API takes.
fn unbyte(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(unbyte).collect()),
        Value::Object(m) if m.len() == 1 && m.contains_key("$bytes") => m["$bytes"].clone(),
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), unbyte(x))).collect()),
        x => x.clone(),
    }
}

/// Numbers compare as f64 (the reference does not distinguish 1 from 1.0).
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| same(p, q))),
        _ => a == b,
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "keyPairFromSeed" => {
            let seed = common::b64d(a[0]["$bytes"].as_str().ok_or("seed")?);
            let k = key_pair_from_seed(&seed)?;
            let b = |x: &[u8]| {
                use base64::Engine;
                let mut m = atlas_pca::serde_json::Map::new();
                m.insert("$bytes".into(), Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x)));
                Value::Object(m)
            };
            Ok(json!({ "secretKey": b(&k.secret_key), "publicKey": b(&k.public_key), "pub": k.public }))
        }
        "buildChain" => build_chain(&unbyte(&a[0])),
        "worsen" => worsen(&a[0], &a[1]),
        "consts" => Ok(json!({ "DEFAULT_SEED": DEFAULT_SEED, "DEFAULT_NUM_RUNS": DEFAULT_NUM_RUNS, "INVARIANT_NAMES": INVARIANT_NAMES })),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn ref_invariants_replay() {
    let cases = common::ref_cases_seeded("invariants");
    let mut bad = Vec::new();
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => same(&c["out"], v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
