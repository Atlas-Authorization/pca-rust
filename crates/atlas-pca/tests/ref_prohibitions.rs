//! Differential replay of test-data/ref-prohibitions.json.gz (written by the TypeScript reference): the constants, the trigger
//! validator and its conservative match, the constitution signer, the non-strict advance, the evidence digest and the composition
//! of a permission verdict with the prohibition veto. A case the reference refuses must be refused here.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::prohibitions::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, thrown};

/// `String(v)` of a label argument.
fn label(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), String::from)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "CONSTITUTION_VERSION": CONSTITUTION_VERSION, "CONSTITUTION_SIG_DOMAIN": CONSTITUTION_SIG_DOMAIN, "EVIDENCE_VERSION": EVIDENCE_VERSION,
            "SAFETY_EVIDENCE_SIG_DOMAIN": SAFETY_EVIDENCE_SIG_DOMAIN, "STATE_DIGEST_DOMAIN": STATE_DIGEST_DOMAIN, "STATE_CHAIN_DOMAIN": STATE_CHAIN_DOMAIN,
            "MAX_LEDGER": MAX_LEDGER, "MAX_INVARIANTS": MAX_INVARIANTS, "MAX_DEADLINE": MAX_DEADLINE,
        }),
        "validateWhen" => json!(atlas_pca::forbid::validate_when(&a[0], &label(&a[1]))),
        "whenMatches" => json!(atlas_pca::forbid::when_matches(&a[0], &a[1])),
        "signConstitution" => a[1]
            .as_str()
            .ok_or_else(|| "not a key".to_string())
            .and_then(KeyPair::from_seed_b64u)
            .and_then(|k| atlas_pca::signers_more::sign_constitution(&k, &a[0]))
            .unwrap_or_else(thrown),
        // the 4th argument is absent (the state's own clock) or present; a present value that is not a number is a clock regression
        "advanceState" => advance_state(&a[0], &a[1], &a[2], a.get(3).map(|n| n.as_f64().unwrap_or(f64::NAN))),
        "evidenceDigest" => evidence_digest(&a[0]).map_or_else(|| thrown("outside the strict JSON profile"), Value::String),
        "composeAuthority" => compose_authority(a[0] == true, &a[1], &a[2], &a[3]).to_json(),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn the_prohibition_surface_matches_the_reference() {
    replay("prohibitions", 1637, 3, run);
}
