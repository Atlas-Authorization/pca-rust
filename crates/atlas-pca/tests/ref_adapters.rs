//! Differential replay of the agent-side adapter helpers (messageSegments, provenanceHeaders and the recorder flow fed through
//! recordMessages / recordInput / recordPrincipal / recordToolResult) against the TypeScript reference
//! (test-data/ref-adapters.json.gz). The recorder's key and session derive from sha256("atlas-pca-conformance/" + label), the clock is
//! fixed, and Ed25519 is deterministic, so the signed bundles compare byte for byte. A reference throw only requires a refusal.
//! Skipped (counted, must stay under 10%): cases with a lone surrogate (no Rust string). Nothing else is skipped.
mod common;
use atlas_pca::adapters::*;
use atlas_pca::arg_provenance::ProvenanceRecorder;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::Operation;
use base64::Engine;
use sha2::{Digest, Sha256};

fn seed_of(label: &str) -> [u8; 32] {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into()
}

fn flow(spec: &Value) -> Result<Value, String> {
    let b64u = |b: [u8; 32]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let rec = ProvenanceRecorder::new("harness", "k1", Some(seed_of("ref-adapters/recorder")))?
        .with_session(&b64u(seed_of("ref-adapters/session")))?
        .with_clock(|| 1_800_000_000_000);
    let mut s = AdapterSession::new(rec);
    let mut bundles = Vec::new();
    for st in spec["steps"].as_array().ok_or("steps")? {
        match st["op"].as_str().ok_or("op")? {
            "messages" => s.record_messages(&st["messages"])?,
            "input" => s.record_input(&st["input"])?,
            "principal" => s.record_principal(st["text"].as_str().ok_or("text")?)?,
            "tool" => s.record_tool_result(st["tool"].as_str().ok_or("tool")?, &st["output"])?,
            "act" => {
                let a = &st["action"];
                let op = Operation::new(a["verb"].as_str().ok_or("verb")?, a["resource"].as_str().ok_or("resource")?, a["params"].clone());
                bundles.push(s.recorder.for_action(&op)?);
            }
            other => return Err(format!("unknown op {other}")),
        }
    }
    Ok(json!({ "bundles": bundles, "receipts": s.recorder.receipts() }))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "messageSegments" => Ok(Value::Array(message_segments(&a[0]))),
        "provenanceHeaders" => {
            let h = provenance_headers(Some(&a[0]))?;
            Ok(Value::Object(h.into_iter().map(|(k, v)| (k, Value::String(v))).collect()))
        }
        "recordFlow" => flow(&a[0]),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn adapters_vectors() {
    let cases = common::ref_cases("adapters");
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
