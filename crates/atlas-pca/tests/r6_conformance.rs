//! Round-6 shared vectors (packages/pca/conformance/vectors.json, gen-conformance-r6.mjs): whole signer-set validation
//! (R6-02, R6-03/R6-04), the signer-set hash in UTF-8 byte order, and malformed input that must be a clean deny, never a
//! panic (R6-05).
mod common;
use atlas_pca::*;
use common::{load, SUPPORTED_SUITES};
use serde_json::Value;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn section(doc: &Value, k: &str) -> Vec<Value> {
    doc["primitives"][k].as_array().unwrap_or_else(|| panic!("missing primitives.{k}")).clone()
}

#[test]
fn threshold_set_matches_reference() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    let mut ran = 0;
    for e in section(&doc, "threshold_set") {
        if let Some(r) = e.get("requires").and_then(Value::as_str) {
            if !SUPPORTED_SUITES.contains(&r) {
                continue;
            }
        }
        ran += 1;
        let want = e["valid"].as_bool().unwrap();
        match catch_unwind(AssertUnwindSafe(|| verify_threshold_share(&e))) {
            Ok(got) if got == want => {}
            Ok(got) => bad.push(format!("{}: got {got} want {want}", e["name"])),
            Err(_) => bad.push(format!("{}: PANIC", e["name"])),
        }
    }
    assert!(ran >= 50, "threshold_set ran {ran}");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn signer_set_hash_matches_reference() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for e in section(&doc, "signer_set_hash") {
        let h = signer_set_hash_b64u(e["signer_set"].as_array().unwrap());
        if h.as_deref() != e["hash"].as_str() {
            bad.push(format!("{}: got {h:?}", e["name"]));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn malformed_is_a_clean_deny() {
    let doc = load("vectors.json");
    let ms = section(&doc, "malformed");
    assert!(ms.len() >= 80);
    let mut bad = Vec::new();
    for m in ms {
        let name = m["name"].as_str().unwrap().to_string();
        let input = &m["input"];
        let r = catch_unwind(AssertUnwindSafe(|| -> bool {
            match m["api"].as_str().unwrap() {
                "chain" => verify_chain(input["chain"].as_array().unwrap(), input["expected_root_issuer"].as_str()).is_ok(),
                "threshold_share" => verify_threshold_share(input),
                "pcactn_json" => {
                    verify_pcactn_json(input["text"].as_str().unwrap(), &input["grant"], input["now"].as_i64().unwrap(), input["aud"].as_str().unwrap()).allow
                }
                other => panic!("unknown api {other}"),
            }
        }));
        match r {
            Ok(false) => {}
            Ok(true) => bad.push(format!("{name}: accepted")),
            Err(_) => bad.push(format!("{name}: PANIC")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Apply a depth case's optional `expand` ({marker, levels, leaf}) ITERATIVELY so the verifier, not the runner, faces
/// the huge value: chain / threshold_share replace the string value equal to `marker` (located by JSON pointer);
/// pcactn_json / json_parse replace the substring `marker` of input.text.
fn expand_depth(e: &Value) -> Value {
    let mut input = e["input"].clone();
    let x = match e.get("expand") {
        Some(x) if x.is_object() => x,
        _ => return input,
    };
    let marker = x["marker"].as_str().unwrap();
    let levels = x["levels"].as_u64().unwrap() as usize;
    let api = e["api"].as_str().unwrap();
    if api == "pcactn_json" || api == "json_parse" {
        let leaf = canonicalize(&x["leaf"]);
        let text = input["text"].as_str().unwrap().replacen(marker, &("[".repeat(levels) + &leaf + &"]".repeat(levels)), 1);
        input["text"] = Value::String(text);
        return input;
    }
    let mut found = None;
    let mut st: Vec<(&Value, String)> = vec![(&input, String::new())];
    while let Some((v, p)) = st.pop() {
        match v {
            Value::String(s) if s == marker => {
                found = Some(p);
                break;
            }
            Value::Array(a) => st.extend(a.iter().enumerate().map(|(i, c)| (c, format!("{p}/{i}")))),
            Value::Object(m) => st.extend(m.iter().map(|(k, c)| (c, format!("{p}/{}", k.replace('~', "~0").replace('/', "~1"))))),
            _ => {}
        }
    }
    let path = found.unwrap_or_else(|| panic!("depth marker not found in {}", e["name"]));
    let mut v = x["leaf"].clone();
    for _ in 0..levels {
        v = Value::Array(vec![v]);
    }
    *input.pointer_mut(&path).unwrap() = v;
    input
}

/// Depth limit-1 / limit / limit+1 / huge on every untrusted-input entry point (primitives.depth): the verdict equals the
/// reference's; no panic and no stack overflow (the huge inputs are leaked so serde_json's recursive Drop is not run).
#[test]
fn depth_vectors_match_reference() {
    let doc = load("vectors.json");
    let ds = section(&doc, "depth");
    assert!(ds.len() >= 29, "depth shrank: {}", ds.len());
    let mut bad = Vec::new();
    for e in ds {
        let name = e["name"].as_str().unwrap().to_string();
        let input = expand_depth(&e);
        let r = catch_unwind(AssertUnwindSafe(|| -> bool {
            match e["api"].as_str().unwrap() {
                "chain" => verify_chain(input["chain"].as_array().unwrap(), input["expected_root_issuer"].as_str()).is_ok(),
                "threshold_share" => verify_threshold_share(&input),
                "pcactn_json" => {
                    verify_pcactn_json(input["text"].as_str().unwrap(), &input["grant"], input["now"].as_i64().unwrap(), input["aud"].as_str().unwrap()).allow
                }
                "json_parse" => strict_parse(input["text"].as_str().unwrap()).is_ok(),
                other => panic!("unknown api {other}"),
            }
        }));
        match r {
            Ok(g) if Some(g) == e["valid"].as_bool() => {}
            Ok(g) => bad.push(format!("{name}: got {g} want {}", e["valid"])),
            Err(_) => bad.push(format!("{name}: PANIC")),
        }
        if e.get("expand").is_some() {
            std::mem::forget(input);
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
