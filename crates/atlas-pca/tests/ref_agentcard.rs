//! Differential replay of signed Agent Cards and AgentFacts against the TypeScript reference (test-data/ref-agentcard.json.gz):
//! JCS bytes, the A2A 1.0 schema check, card build / sign / verify, AgentFacts issue / attest / verify, the hosting handlers
//! and the registry entry. Ed25519 is deterministic, so signed output compares byte for byte. JOSE library texts after
//! "signature N did not verify" / "could not resolve verification key" are cut at the colon on both sides (as the generator
//! does); a reference throw must be a refusal (the package's own `issueSignedAgentCard:` texts compare exactly).
mod common;
use atlas_pca::agentcard::*;
use atlas_pca::serde_json::{json, Value};

static NULL: Value = Value::Null;

fn fix(s: &str) -> String {
    for p in ["could not resolve verification key", "signature did not verify"] {
        if s.starts_with(&format!("{p}: ")) {
            return p.into();
        }
    }
    if let Some(rest) = s.strip_prefix("signature ") {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !digits.is_empty() && rest[digits.len()..].starts_with(" did not verify: ") {
            return format!("signature {digits} did not verify");
        }
    }
    s.into()
}

fn norm(mut v: Value) -> Value {
    if let Some(r) = v.get("reason").and_then(Value::as_str).map(fix) {
        v["reason"] = json!(r);
    }
    if let Some(a) = v.get_mut("attestations").and_then(Value::as_array_mut) {
        for x in a {
            if let Some(r) = x.get("reason").and_then(Value::as_str).map(fix) {
                x["reason"] = json!(r);
            }
        }
    }
    v
}

fn octets(b: &[u8]) -> Value {
    Value::Array(b.iter().map(|x| json!(x)).collect())
}

fn same(want: &Value, got: Result<Value, String>) -> Result<(), String> {
    let want_n = match want.get("$bytes").and_then(Value::as_str).and_then(|s| atlas_pca::decode_b64u_strict(s, None)) {
        Some(b) => octets(&b),
        None => want.clone(),
    };
    match (want.get("$throws").and_then(Value::as_str), got) {
        (Some(w), Err(g)) if !w.starts_with("issueSignedAgentCard:") || w == g => Ok(()),
        (None, Ok(g)) if atlas_pca::canonicalize(&want_n) == atlas_pca::canonicalize(&g) => Ok(()),
        (_, g) => Err(format!("want {want}, got {g:?}")),
    }
}

#[test]
fn agentcard_vectors() {
    let cases = common::ref_cases_seeded("agentcard");
    let (mut bad, mut skipped) = (Vec::new(), 0usize);
    for c in &cases {
        if c.to_string().contains(common::LONE) {
            skipped += 1;
            continue;
        }
        let a = c["args"].as_array().unwrap();
        let g = |i: usize| a.get(i).unwrap_or(&NULL);
        let opt_str = |i: usize| g(i).as_str();
        let got: Result<Value, String> = match c["fn"].as_str().unwrap() {
            "constants" => Ok(constants()),
            "jcsBytes" => jcs_bytes(g(0)).map(|b| octets(&b)),
            "validateAgentCard1" => Ok(json!(validate_agent_card1(g(0)))),
            "buildAgentCard" => build_agent_card(g(0), g(1)),
            "issueSignedAgentCard" => issue_signed_agent_card(g(0), g(1), a.get(2).unwrap_or(&json!({}))),
            "verifyAgentCard" => Ok(norm(verify_agent_card(g(0), g(1)))),
            "issueAgentFacts" => issue_agent_facts(g(0), g(1)),
            "addAttestation" => add_attestation(g(0), g(1)),
            "verifyAgentFacts" => verify_agent_facts(g(0), g(1)).map(norm),
            "agentCardHandler" => match g(2).as_str() {
                Some(r) => Ok(agent_card_handler(g(0), opt_str(1), r)),
                None => {
                    skipped += 1;
                    continue;
                }
            },
            "agentFactsHandler" => match g(2).as_str() {
                Some(r) => Ok(agent_facts_handler(g(0), opt_str(1), r)),
                None => {
                    skipped += 1;
                    continue;
                }
            },
            "toRegistryEntry" => to_registry_entry(g(0), g(1)),
            other => panic!("unknown fn {other}"),
        };
        if let Err(e) = same(&c["out"], got) {
            bad.push(format!("{}: {e}", c["name"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "too many skipped: {skipped}");
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}
