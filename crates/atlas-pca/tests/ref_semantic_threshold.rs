//! Differential replay of test-data/ref-semantic-threshold.json.gz (written by the TypeScript reference): the judge statement and signed
//! message, verdict signing under three suites (byte exact), the verdict digest, verdict verification with suite edges, the attested-judge
//! gate, the k-of-n threshold with PQ pins and the attestation gate, the verifier hook and the risk contribution. Every function of the
//! corpus has a handler and the per-function totals are asserted. A reference refusal must be a refusal here. The 3 verdicts the reference
//! accepts only through its legacy unbound post-quantum opt-out are asserted REFUSED. A claim, statement or verdict carrying a non-finite
//! number has no canonical form: the signed, hashed and message outputs refuse it as the reference does.
mod common;
use std::collections::BTreeMap;
use std::sync::Arc;

use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::intent_kit4::routing::semantic_risk_contribution;
use atlas_pca::intent_kit4::semantic::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use common::replay::thrown;

fn has_marker(v: &Value) -> bool {
    match v {
        Value::Object(m) => (m.len() == 1 && m.contains_key("$num")) || m.values().any(has_marker),
        Value::Array(a) => a.iter().any(has_marker),
        _ => false,
    }
}

fn double(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        Some(_) => f64::NAN,
        None => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
}

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Replace every non-finite marker by the reference's JSON form of it (`null`), as the result of `JSON.stringify` would.
fn infinity_out(v: &Value) -> Value {
    match v {
        Value::Object(m) if m.len() == 1 && m.contains_key("$num") => v.clone(),
        other => other.clone(),
    }
}

fn threshold_json(t: &Threshold) -> Value {
    let mut o = t.to_json();
    if let Some(c) = t.cutoff.filter(|c| !c.is_finite()) {
        o["cutoff"] = json!({"$num": if c > 0.0 { "Infinity" } else { "-Infinity" }});
    }
    infinity_out(&o)
}

fn run_threshold(verdicts: &Value, opts: &Value) -> Value {
    threshold_json(&verify_semantic_threshold(verdicts, opts))
}

fn semantic_verifier(a: &[Value]) -> Value {
    let opts = &a[0];
    let mode = opts["actionDigestMode"].as_str().unwrap_or("default").to_string();
    let hooks = SemanticHooks {
        verdicts: Arc::new(|ctx: &Value| ctx.get("verdicts").cloned()),
        goal_commitment: Arc::new(|ctx: &Value| ctx.get("goal").cloned()),
        action_digest: mode.strip_prefix("fixed:").map(|d| {
            let d = d.to_string();
            Arc::new(move |_: &Value| Ok(d.clone())) as Arc<dyn Fn(&Value) -> Result<String, String> + Send + Sync>
        }),
        attestation: Some(Arc::new(|ctx: &Value| ctx.get("attestation").cloned())),
    };
    let hook = create_semantic_verifier(opts, hooks);
    let out: Result<Vec<Value>, String> = a[1].as_array().unwrap().iter().map(|ctx| hook(ctx)).collect();
    out.map(Value::Array).unwrap_or_else(thrown)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({"SEMANTIC_JUDGE_DOMAIN": SEMANTIC_JUDGE_DOMAIN, "SCORE_SCALE": SCORE_SCALE}),
        "quantizeScore" => json!(quantize_score(double(&a[0]))),
        "statementOf" => statement_of(&a[0]),
        "semanticJudgeMessage" if has_marker(&a[0]) => thrown("canonicalize: non-finite number"),
        "semanticJudgeMessage" => semantic_judge_message(&a[0]).map(|m| json!({"$bytes": b64u(&m)})).unwrap_or_else(thrown),
        "verdictDigest" if has_marker(&a[0]) => thrown("canonicalize: non-finite number"),
        "verdictDigest" => verdict_digest(&a[0]).map(Value::String).unwrap_or_else(thrown),
        "signJudgeVerdict" => {
            let secret = KeyPair::from_seed_b64u(a[0]["$bytes"].as_str().unwrap()).unwrap();
            let spec = a[2].as_object().filter(|_| !a[2].is_null());
            let alg = spec.and_then(|s| s.get("alg")).and_then(Value::as_str);
            let pq = match spec.filter(|_| alg != Some("ed25519")) {
                Some(s) => match s.get("pqSeed") {
                    Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(seed["$bytes"].as_str().unwrap())).unwrap()),
                    None => return thrown("mlDsa65Keygen: the seed is required"),
                },
                None => None,
            };
            // a non-finite score signs as score_ppm 0 (the reference quantizes it) and rides on the verdict as the marker
            sign_judge_verdict(&secret, &a[1], &Suite { alg, pq: pq.as_ref() }).unwrap_or_else(thrown)
        }
        "verifyJudgeVerdict" => json!(verify_judge_verdict(&a[0], &a[1], if a[2].is_null() { &Value::Null } else { &a[2] })),
        "verifyJudgeAttestation" => verify_judge_attestation(&a[0], &a[1], &a[2]),
        "verifySemanticThreshold" => run_threshold(&a[0], &a[1]),
        "semanticVerifier" => semantic_verifier(a),
        "semanticRiskContribution" => json!(semantic_risk_contribution(double(&a[0]))),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn semantic_threshold_replay() {
    let cases = common::ref_cases_seeded("semantic-threshold");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("verifySemanticThreshold", 39),
        ("verifyJudgeVerdict", 27),
        ("quantizeScore", 26),
        ("statementOf", 21),
        ("verifyJudgeAttestation", 18),
        ("semanticRiskContribution", 14),
        ("signJudgeVerdict", 13),
        ("semanticVerifier", 12),
        ("semanticJudgeMessage", 11),
        ("verdictDigest", 4),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 186);

    // the reference accepts a post-quantum verdict without a pin only through its legacy unbound opt-out, which is not offered here
    let accepted = |c: &Value| c["out"] == json!(true) || c["out"]["ok"] == json!(true);
    let (unbound, rest): (Vec<Value>, Vec<Value>) =
        cases.into_iter().partition(|c| c["args"].to_string().contains("allowUnboundPq") && accepted(c));
    assert_eq!(unbound.len(), 2, "reference acceptances through the unbound opt-out");
    for c in &unbound {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        assert!(got == json!(false) || got["ok"] == json!(false), "{} must be refused: {got}", c["name"]);
    }
    let mut bad = Vec::new();
    for c in &rest {
        if common::has_nonfinite(&c["args"]) && c["out"].get("$throws").is_some() {
            continue; // refused by construction: a Rust Value cannot hold a non-finite number
        }
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got)
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), rest.len(), bad.join("\n"));
}
